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

import datetime
import os
import tempfile

import magic
import pefile
from viper2 import printer
from viper2.common.errors import ERROR_NO_OPEN_FILE
from viper2.common.file import FileObject
from viper2.common.module import Module, ModuleRunError
from viper2.core.sessions import sessions


class PE(Module):
    cmd = "pe"
    description = "Analyse PE32 binaries"
    authors = ["Claudio Guarnieri"]
    license = "BSD-3-Clause"

    def __init__(self) -> None:
        super().__init__()
        subparsers = self.args_parser.add_subparsers(dest="subname")
        subparsers.add_parser("entrypoint", help="Show PE address of entry point")
        subparsers.add_parser("compiletime", help="Show PE compile time")
        subparsers.add_parser("imports", help="List imports")
        subparsers.add_parser("exports", help="List exports")
        subparsers.add_parser("sections", help="List sections")
        resources = subparsers.add_parser("resources", help="List resources")
        resources.add_argument(
            "-o", "--open", help="Open a session to the specified resource"
        )

        self.pe = None

    @staticmethod
    def supports_file(file_object: FileObject) -> bool:
        if file_object.magic.startswith("PE32"):
            return True

        return False

    def entrypoint(self) -> None:
        printer.info(hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint))

    def compiletime(self) -> None:
        printer.info(
            "%s (%s)",
            self.pe.FILE_HEADER.TimeDateStamp,
            datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp),
        )

    def imports(self) -> None:
        counter = 0
        for library in self.pe.DIRECTORY_ENTRY_IMPORT:
            if counter > 0:
                print("")

            printer.info("[bold]%s[/]", library.dll.decode())

            rows = []
            for symbol in library.imports:
                rows.append([hex(symbol.address), symbol.name.decode()])

            printer.table(columns=["Address", "Name"], rows=rows)
            counter += 1

    def exports(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        rows = []
        for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            rows.append(
                [
                    hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address),
                    symbol.name,
                    symbol.ordinal,
                ]
            )

        printer.table(columns=["Address", "Name", "Ordinal"], rows=rows)

    def sections(self) -> None:
        rows = []
        for section in self.pe.sections:
            rows.append(
                [
                    section.Name.decode().replace("\x00", ""),
                    hex(section.VirtualAddress),
                    hex(section.Misc_VirtualSize),
                    hex(section.PointerToRawData),
                    str(section.SizeOfRawData),
                    str(section.get_entropy()),
                ]
            )

        printer.table(
            columns=[
                "Name",
                "RVA",
                "VirtualSize",
                "PointerToRawData",
                "RawDataSize",
                "Entropy",
            ],
            rows=rows,
        )

    def resources(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            printer.info("The binary does not contain resources")
            return

        rows = []
        for res_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.name:
                name = str(res_type.name)
            else:
                name = str(pefile.RESOURCE_TYPE.get(res_type.struct.Id))

            if not name:
                name = str(res_type.struct.Id)

            for resource_id in res_type.directory.entries:
                for resource in resource_id.directory.entries:
                    lang = pefile.LANG.get(resource.data.lang, None)
                    sublang = pefile.get_sublang_name_for_lang(
                        resource.data.lang, resource.data.sublang
                    )
                    offset = resource.data.struct.OffsetToData
                    offset_hex = f"0x{offset:08x}"
                    size = resource.data.struct.Size
                    data = self.pe.get_data(offset, size)
                    data_magic = magic.from_buffer(data)

                    if self.args.open and self.args.open == offset_hex:
                        tmpdir = tempfile.mkdtemp()
                        new_file_path = os.path.join(tmpdir, f"{offset_hex}.bin")
                        with open(new_file_path, "wb") as handle:
                            handle.write(data)

                        sessions.new(new_file_path)
                        return

                    rows.append(
                        [
                            offset_hex,
                            name,
                            str(size),
                            f"{lang} / {sublang}",
                            data_magic,
                        ]
                    )

        printer.table(
            columns=["Offset", "Resource Type", "Size", "Language", "Magic"],
            rows=rows,
        )

    def run(self) -> None:
        try:
            super().run()
        except ModuleRunError:
            return

        if not sessions.current:
            printer.error(ERROR_NO_OPEN_FILE)
            return

        self.pe = pefile.PE(sessions.current.file.path)

        subcommands = {
            "entrypoint": self.entrypoint,
            "compiletime": self.compiletime,
            "imports": self.imports,
            "exports": self.exports,
            "sections": self.sections,
            "resources": self.resources,
        }

        if self.args.subname in subcommands:
            subcommands[self.args.subname]()
        else:
            self.args_parser.print_usage()
