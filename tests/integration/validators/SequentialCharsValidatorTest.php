<?php

use craftpulse\passwordpolicy\validators\SequentialCharsValidator;

beforeEach(function() {
    $this->validator = new SequentialCharsValidator();
});

it('rejects ascending letter sequences', function() {
    expect($this->validator->validateValue('myabcpass'))->not->toBeNull();
});

it('rejects descending letter sequences', function() {
    expect($this->validator->validateValue('mycbapass'))->not->toBeNull();
});

it('rejects ascending number sequences', function() {
    expect($this->validator->validateValue('my123pass'))->not->toBeNull();
});

it('rejects descending number sequences', function() {
    expect($this->validator->validateValue('my321pass'))->not->toBeNull();
});

it('rejects keyboard row sequences like qwe', function() {
    expect($this->validator->validateValue('myqwepass'))->not->toBeNull();
});

it('rejects keyboard row sequences like asd', function() {
    expect($this->validator->validateValue('myasdpass'))->not->toBeNull();
});

it('rejects reversed keyboard sequences', function() {
    expect($this->validator->validateValue('myewqpass'))->not->toBeNull();
});

it('accepts non-sequential passwords', function() {
    expect($this->validator->validateValue('Hx9$mK2p'))->toBeNull();
});

it('accepts sequences shorter than 3 characters', function() {
    expect($this->validator->validateValue('myabXpass'))->toBeNull();
});

it('is case-insensitive', function() {
    expect($this->validator->validateValue('myABCpass'))->not->toBeNull();
});
