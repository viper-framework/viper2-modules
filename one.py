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

import os
import re
import struct
import tempfile
from dataclasses import dataclass
from typing import List

import magic
from rich.console import Console
from rich.syntax import Syntax
from viper2 import printer
from viper2.common.errors import ERROR_NO_OPEN_FILE
from viper2.common.file import FileObject
from viper2.common.module import Module, ModuleRunError
from viper2.core.sessions import sessions

ONE_MAGIC = bytes(
    [
        0xE4,
        0x52,
        0x5C,
        0x7B,
        0x8C,
        0xD8,
        0xA7,
        0x4D,
        0xAE,
        0xB1,
        0x53,
        0x78,
        0xD0,
        0x29,
        0x96,
        0xD3,
    ]
)
EMBEDDED_FILE_GUID = bytes(
    [
        0xE7,
        0x16,
        0xE3,
        0xBD,
        0x65,
        0x26,
        0x11,
        0x45,
        0xA4,
        0xC4,
        0x8D,
        0x4D,
        0x0B,
        0x7A,
        0x9E,
        0xAC,
    ]
)


def is_onenote(file_path: str) -> bool:
    with open(file_path, "rb") as handle:
        header = handle.read(16)
        if header == ONE_MAGIC:
            return True


@dataclass
class EmbeddedFile:
    offset: str
    magic: str
    data: bytes


class One(Module):
    cmd = "one"
    description = "Analyse OneNote documents"
    authors = ["Claudio Guarnieri"]
    license = "BSD-3-Clause"

    def __init__(self) -> None:
        super().__init__()

        self.args_parser.add_argument(
            "-o",
            "--open",
            metavar="OFFSET",
            help="open the embedded file at specified offset",
        )

    @staticmethod
    def supports_file(file_object: FileObject) -> bool:
        return is_onenote(file_object.path)

    def __find_embedded(self, raw: bytes) -> List[dict]:
        matches = re.finditer(EMBEDDED_FILE_GUID, raw, re.DOTALL)
        if not matches:
            return []

        files = []
        for _, match in enumerate(matches):
            offset = match.start()

            size_offset = offset + 16
            size_value = raw[size_offset : size_offset + 4]

            data_size = struct.unpack("<I", bytearray(size_value))[0]
            data_start = match.start() + 36
            data = raw[data_start : data_start + data_size]
            data_magic = magic.Magic().from_buffer(data)

            files.append(
                EmbeddedFile(offset=str(hex(offset)), magic=data_magic, data=data)
            )

        return files

    def __open_embedded(self, files: List[EmbeddedFile], offset: str) -> None:
        data = None
        for file in files:
            if file.offset == offset:
                data = file.data
                break

        if not data:
            printer.error("Could not file embedded file at specified offset")
            return

        tmpdir = tempfile.mkdtemp()
        new_file_path = os.path.join(tmpdir, f"{offset}.bin")
        with open(new_file_path, "wb") as handle:
            handle.write(data)

        sessions.new(new_file_path)

    def __print_embedded(self, files: List[EmbeddedFile]) -> None:
        rows = []
        for file in files:
            has_pe = False
            has_hta = False
            has_powershell = False
            if "ASCII" in file.magic:
                data_decoded = file.data.decode()
                if "hta:application" in data_decoded.lower():
                    has_hta = True
                if "powershell" in data_decoded.lower():
                    has_powershell = True

                console = Console()
                syntax = Syntax(
                    data_decoded.lstrip(),
                    lexer="powershell",
                    theme="material",
                    word_wrap=True,
                )

                printer.info("Found potential executable script:")
                console.print(syntax)
                print("")
            elif "PE32" in file.magic:
                has_pe = True

            rows.append(
                [
                    file.offset,
                    file.magic,
                    "Yes" if has_pe else "",
                    "Yes" if has_powershell else "",
                    "Yes" if has_hta else "",
                ]
            )

        printer.info("Embedded files:")
        printer.table(
            columns=[
                "Offset",
                "Magic",
                "Executable",
                "PowerShell",
                "HTA",
            ],
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

        if not is_onenote(sessions.current.file.path):
            printer.error("The open file is not a OneNote document")
            return

        with open(sessions.current.file.path, "rb") as handle:
            data = handle.read()

        files = self.__find_embedded(data)
        if not files:
            printer.info("No embedded files found")
            return

        if self.args.open:
            self.__open_embedded(files, self.args.open)
            return

        self.__print_embedded(files)
