PROJECT = gb_merkle_trees
PROJECT_DESCRIPTION = General balanced Merkle trees
PROJECT_VERSION = 0.2.0

TEST_DEPS = triq
dep_triq = git https://github.com/triqng/triq.git master

# Whitespace to be used when creating files from templates.
SP = 2

include erlang.mk
