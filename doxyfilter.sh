#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright © 2007-2018 ANSSI. All Rights Reserved.

exec sed -e '/^MODULE_/d; /^module_/d; /^[a-z]\+_initcall/d; /^EXPORT_/d ' $*
