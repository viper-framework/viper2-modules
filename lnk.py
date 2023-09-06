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

from LnkParse3.lnk_file import LnkFile
from rich.console import Console
from rich.syntax import Syntax
from viper2 import printer
from viper2.common.errors import ERROR_NO_OPEN_FILE
from viper2.common.file import FileObject
from viper2.common.module import Module, ModuleRunError
from viper2.core.sessions import sessions


class LNK(Module):
    cmd = "lnk"
    description = "Analyse Windows .lnk files"
    authors = ["Claudio Guarnieri"]
    license = "BSD-3-Clause"

    @staticmethod
    def supports_file(file_object: FileObject) -> bool:
        if "MS Windows shortcut" in file_object.magic:
            return True

    def run(self) -> None:
        try:
            super().run()
        except ModuleRunError:
            return

        if not sessions.current:
            printer.error(ERROR_NO_OPEN_FILE)
            return

        with open(sessions.current.file.path, "rb") as handle:
            lnk = LnkFile(handle)

        printer.info("[bold]Icon location:[/] %s", lnk.string_data.icon_location())

        print("")

        printer.info("[bold]Extra data:[/]")
        for extra_key, extra_value in lnk.extras.as_dict().items():
            printer.info("  %s", extra_key)
            for key, value in extra_value.items():
                printer.info("    %s: %s", key, value)

        print("")

        cmd_args = lnk.string_data.command_line_arguments()
        printer.info("[bold]Command line arguments:[/]")
        console = Console()
        syntax = Syntax(cmd_args, lexer="powershell", theme="material", word_wrap=True)
        console.print(syntax)
