'use strict';

module.exports = {
  message: 'Hello',
  key_material: new Uint8Array([5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246]),
  assert_is_not_zeros: function(array) {
    var only_zeroes = true;
    for (var index = 0; index < array.length; ++index) {
      if (array[index] > 0) {
        only_zeroes = false;
        break;
      }
    }
    return (only_zeroes === false);
  }
};
