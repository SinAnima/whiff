"""Macros for harbour targets."""

load("@bazel_skylib//lib:paths.bzl", "paths")

def harbour_test(name, srcs):
    native.py_test(name = name, srcs = srcs)
