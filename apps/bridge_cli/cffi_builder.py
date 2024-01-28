# ==============================================================================
#
# Copyright 2023 ETRI All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"),
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Created on: Aug 20, 2023,
#        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
#
#
# ==============================================================================


from cffi import FFI
import argparse as ap
import sys


try:
    if len(sys.argv) == 1:
        sys.argv = [
            "cffi_builder.py",
            "--header_path",
            "/home/jclee/Development/Matter/WS_Matter/bridge_manager",
            "--module_path",
            "/home/jclee/Development/Matter/WS_Matter/bridge_manager/out",
        ]

    # Create an ArgumentParser object
    parser = ap.ArgumentParser(
        description="cffi builder for bridge manager integration"
    )

    # Define arguments
    parser.add_argument("--header_path", type=str, help='path of "bridge_manager.h"')
    parser.add_argument(
        "--module_path", type=str, help='path of "libbridge_manager.so"'
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    include_dirs = ["/usr/local/include/iotivity-lite", "/usr/local/include/tinycbor"]
    include_dirs.append(args.header_path)

    ffi = FFI()

    ffi.set_source(
        "bridge_manager",
        """
        #include "bridge_manager.h"
        """,
        include_dirs=include_dirs,
        define_macros=[("OC_BRG_DEBUG", "1")],
        libraries=["bridge_manager"],
        library_dirs=[args.module_path],
        extra_link_args=["-Wl,-rpath=" + args.module_path],
    )

    ffi.cdef(open("./bridge_manager.cdef").read())

except BaseException as e:
    print(e)
    exit(1)


if __name__ == "__main__":
    ffi.compile(verbose=True)
