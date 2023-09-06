# Copyright 2023 Claudio Guarnieri
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import xml.etree.ElementTree as ET
import zipfile
from typing import List

import olefile
from oletools import msodde, olevba
from oletools.ftguess import FileTypeGuesser
from rich.console import Console
from rich.syntax import Syntax
from viper2 import printer
from viper2.common.errors import ERROR_NO_OPEN_FILE
from viper2.common.file import FileObject
from viper2.common.module import Module, ModuleRunError
from viper2.common.sanitize import sanitize_url
from viper2.core.sessions import sessions


def is_ole(file_path: str) -> bool:
    ftg = FileTypeGuesser(file_path)
    return ftg.is_ole()


def is_openxml(file_path: str) -> bool:
    ftg = FileTypeGuesser(file_path)
    return ftg.is_openxml()


# TODO: This is just testing/experimental. Need to replace this function with an
#       appropriate procedure to detect potential document exploits.
def check_target(target: str) -> List[str]:
    cves = []

    if target.lower().endswith(".rtf"):
        cves.append("CVE-2017-0199")

    if target.lower().startswith("mhtml:") and "!x-usc:" in target.lower():
        cves.append("CVE-2021-40444")

    if target.lower().endswith("!"):
        cves.append("CVE-2022-30190")

    return cves


class Office(Module):
    cmd = "office"
    description = "Analyse Microsoft Office documents"
    authors = ["Claudio Guarnieri"]
    license = "BSD-3-Clause"

    def __init__(self) -> None:
        super().__init__()
        subparsers = self.args_parser.add_subparsers(dest="subname")
        subparsers.add_parser("info", help="Display information about the Office file")
        subparsers.add_parser("streams", help="Display streams from the Office file")
        subparsers.add_parser("macros", help="Extract embedded Macros")

        self.ftg = None

    @staticmethod
    def supports_file(file_object: FileObject) -> bool:
        if is_ole(sessions.current.file.path):
            return True

        if (
            is_openxml(sessions.current.file.path)
            and "Microsoft" in sessions.current.file.magic
        ):
            return True

    def info(self):
        rows = [
            ["Is OLE", "Yes" if self.ftg.is_ole() else ""],
            ["Is OpenXML", "Yes" if self.ftg.is_openxml() else ""],
            ["Is Word", "Yes" if self.ftg.is_word() else ""],
            ["Is Excel", "Yes" if self.ftg.is_excel() else ""],
            ["Is PowerPoint", "Yes" if self.ftg.is_powerpoint() else ""],
            [
                "Has Macros",
                "Yes" if len(self.get_macros(sessions.current.file.path)) > 0 else "",
            ],
            [
                "Has DDE",
                "Yes" if len(self.get_dde(sessions.current.file.path)) > 0 else "",
            ],
        ]

        printer.table(columns=["Key", "Value"], rows=rows)

        if self.ftg.is_openxml():
            targets = self.get_external_targets(sessions.current.file.path)
            for target in targets:
                printer.info('Found an external target: "%s"', sanitize_url(target))
                cves = check_target(target)
                for cve in cves:
                    printer.info("Could be %s", cve)

    @staticmethod
    def get_external_targets(file_path):
        with zipfile.ZipFile(file_path, "r") as zip_file:
            for name in zip_file.namelist():
                if (
                    name != "word/_rels\\document.xml.rels"
                    and name != "word/_rels/document.xml.rels"
                ):
                    continue

                targets = []
                with zip_file.open(name) as file:
                    tree = ET.parse(file)
                    root = tree.getroot()
                    for item in root.iter():
                        target_mode = item.get("TargetMode")
                        if target_mode == "External":
                            targets.append(item.get("Target"))

                return targets

    def ole_streams(self):
        ole = olefile.OleFileIO(sessions.current.file.path)

        rows = [
            [
                "1",
                "Root",
                f'{ole.root.getctime() if ole.root.getctime() else ""}',
                f'{ole.root.getmtime() if ole.root.getmtime() else ""}',
            ]
        ]

        counter = 2
        for obj in ole.listdir(streams=True, storages=True):
            rows.append(
                [
                    str(counter),
                    "/".join(obj),
                    f'{ole.root.getctime() if ole.root.getctime() else ""}',
                    f'{ole.root.getmtime() if ole.root.getmtime() else ""}',
                ]
            )

            counter += 1

        printer.info("OLE Structure:")
        printer.table(columns=["#", "Object", "Creation", "Modified"], rows=rows)

        ole.close()

    @staticmethod
    def get_macros(file_path: str) -> List[list]:
        vba_parser = olevba.VBA_Parser(file_path)
        macros = []
        for macro in vba_parser.extract_macros():
            _, stream_path, vba_filename, vba_code = macro
            macros.append([stream_path, vba_filename, vba_code])

        return macros

    def macros(self):
        if not self.ftg.is_ole() and not self.ftg.is_openxml():
            printer.error(
                "The open file is neither OLE or OpenXML, cannot extract macros"
            )
            return

        macros = self.get_macros(sessions.current.file.path)
        for macro in macros:
            printer.info("Stream path: [bold]%s[/]", macro[0])
            printer.info("VBA file name: [bold]%s[/]", macro[1])
            printer.info("Code:")

            console = Console()
            syntax = Syntax(
                macro[2], lexer="vbscript", theme="material", word_wrap=True
            )
            console.print(syntax)

            print("")

        printer.info("Found a total of %d macros", len(macros))

    @staticmethod
    def get_dde(file_path: str) -> List[list]:
        dde_result = msodde.process_file(sessions.current.file.path, "only dde")
        dde_fields = [[i + 1, x.strip()] for i, x in enumerate(dde_result.split("\n"))]
        if (len(dde_fields) == 1) and (dde_fields[0][1] == ""):
            return []

        return dde_fields

    def dde(self) -> None:
        dde_fields = self.get_dde(sesions.current.file.path)

        if not dde_fields:
            printer.info("No DDE links detected")
            return
        else:
            printer.info("DDE links detected")
            header = ["#", "DDE"]
            printer.table(columns=["#", "DDE"], rows=dde_fields)

    def run(self) -> None:
        try:
            super().run()
        except ModuleRunError:
            return

        if not sessions.current:
            printer.error(ERROR_NO_OPEN_FILE)
            return

        self.ftg = FileTypeGuesser(sessions.current.file.path)

        if self.args.subname == "info":
            self.info()
        elif self.args.subname == "streams":
            if self.ftg.is_ole():
                self.ole_streams()
            else:
                printer.error("File type not supported")
        elif self.args.subname == "macros":
            self.macros()
        else:
            self.args_parser.print_usage()
