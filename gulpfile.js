'use strict';

const gulp = require('gulp');
const mocha = require('gulp-mocha');

gulp.task('test', () => gulp.src(['test/*.test.js']).pipe(mocha()));
