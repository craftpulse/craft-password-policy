<?php

use craftpulse\passwordpolicy\validators\RepeatedCharsValidator;

beforeEach(function() {
    $this->validator = new RepeatedCharsValidator();
});

it('rejects three repeated letters', function() {
    expect($this->validator->validateValue('myaaapass'))->not->toBeNull();
});

it('rejects three repeated numbers', function() {
    expect($this->validator->validateValue('my111pass'))->not->toBeNull();
});

it('rejects three repeated symbols', function() {
    expect($this->validator->validateValue('my!!!pass'))->not->toBeNull();
});

it('rejects four or more repeated characters', function() {
    expect($this->validator->validateValue('myaaaapass'))->not->toBeNull();
});

it('accepts two repeated characters', function() {
    expect($this->validator->validateValue('myaapass'))->toBeNull();
});

it('accepts non-repeated passwords', function() {
    expect($this->validator->validateValue('Hx9$mK2p'))->toBeNull();
});

it('accepts alternating characters', function() {
    expect($this->validator->validateValue('ababab'))->toBeNull();
});
