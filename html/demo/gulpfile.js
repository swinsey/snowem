var gulp = require('gulp');
var uglify = require('gulp-uglify');
var pump = require('pump');
var annotate = require('gulp-ng-annotate');
var sourcemaps = require('gulp-sourcemaps');
var concat = require('gulp-concat');

gulp.task('minify', function() {
  return gulp.src('js/app.js')
    .pipe(sourcemaps.init())
    .pipe(concat('app-obs.js'))
    //.pipe(rename('all.min.js'))
    .pipe(annotate())
    .pipe(uglify())
    .pipe(gulp.dest('js'))
});


