/*
 * Wire
 * Copyright (C) 2017 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/* eslint no-magic-numbers: off */

module.exports = {
  assert_is_not_zeros: array => {
    let only_zeroes = true;
    for (let index = 0; index < array.length; ++index) {
      if (array[index] > 0) {
        only_zeroes = false;
        break;
      }
    }
    return only_zeroes === false;
  },
  key_material: new Uint8Array([
    5,
    30,
    208,
    218,
    140,
    173,
    89,
    133,
    238,
    120,
    243,
    172,
    56,
    0,
    84,
    80,
    225,
    83,
    110,
    68,
    59,
    136,
    105,
    202,
    200,
    243,
    73,
    174,
    28,
    38,
    66,
    246,
  ]),
  message: 'Hello',
};
