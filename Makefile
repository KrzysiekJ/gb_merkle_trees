PROJECT = gb_merkle_trees
PROJECT_DESCRIPTION = General balanced Merkle trees
PROJECT_VERSION = 0.2.1

TEST_DEPS = triq
dep_triq = git https://gitlab.com/triq/triq.git e5ba907a11985bf8150f5b5b332d39516ab15857

LOCAL_DEPS = crypto

# Whitespace to be used when creating files from templates.
SP = 2

include erlang.mk
