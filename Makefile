PROJECT = gb_merkle_trees
PROJECT_DESCRIPTION = General balanced Merkle trees
PROJECT_VERSION = 0.1.1

DEPS = triq
dep_triq = git git@github.com:triqng/triq.git master

# Whitespace to be used when creating files from templates.
SP = 2

include erlang.mk
