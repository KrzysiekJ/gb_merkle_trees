%% Licensed under the Apache License, Version 2.0 (the “License”);
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an “AS IS” BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @doc General balanced binary Merkle trees. Similar to {@link //stdlib/gb_trees}, but with Merkle proofs.
%%
%% Keys and values need to be binaries. Values are stored only in leaf nodes to shorten Merkle proofs.
%%
%% Hashes of leaf nodes are based on concatenation of hashes of key and value. Hashes of inner nodes are based on concatenation of hashes of left and right node.
%%
%% Similarly as in {@link //stdlib/gb_trees}, deletions do not cause trees to rebalance.
%%
%% SHA-256 is used as the default hashing algorithm. You can define the `GB_MERKLE_TREES_HASH_ALGORITHM' macro to use another algorithm. See documentation of {@link //crypto/crypto:hash/2} for available choices.
%%
%% @author Krzysztof Jurewicz <krzysztof.jurewicz@gmail.com> [http://jurewicz.org.pl]
%%
%% @reference See <a href="http://cglab.ca/~morin/teaching/5408/refs/a99.pdf">Arne Andersson’s “General Balanced Trees” article</a> for insights about the balancing algorithm. The original balance condition has been changed to 2^h(T) ≤ |T|^2.
%% @reference See <a href="https://github.com/tendermint/go-merkle">go-merkle</a> for a similar in purpose library written in Go which uses AVL trees instead of general balanced trees.
%% @see //stdlib/gb_trees
%% @see //crypto/crypto:hash/2

-module(gb_merkle_trees).
-export([balance/1,
         delete/2,
         empty/0,
         enter/3,
         foldr/3,
         from_list/1,
         from_orddict/1,
         from_orddict/2,
         lookup/2,
         merkle_proof/2,
         root_hash/1,
         size/1,
         to_orddict/1]).

-ifdef(TEST).
-include_lib("triq/include/triq.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

-ifndef(GB_MERKLE_TREES_HASH_ALGORITHM).
-define(GB_MERKLE_TREES_HASH_ALGORITHM, sha256).
-endif.
-define(HASH(X), crypto:hash(?GB_MERKLE_TREES_HASH_ALGORITHM, X)).

%% Trees are balanced using the condition 2^h(T) ≤ |T|^C
-define(C, 2).

-type key() :: binary().
-type value() :: binary().
-type hash() :: binary().

%% We distinguish inner nodes and tree nodes by tuple length instead of using records to save some space.
-type leaf_node() :: {key(), value(), hash()}.
-type inner_node() :: {key(), hash() | to_be_computed, Left :: inner_node() | leaf_node(), Right :: inner_node() | leaf_node()}.
-type tree_node() :: leaf_node() | inner_node() | empty.
-opaque tree() :: {Size :: non_neg_integer(), RootNode :: tree_node()}.
-type merkle_proof() :: {hash() | merkle_proof(), hash() | merkle_proof()}.

-export_type(
   [key/0,
    value/0,
    hash/0,
    tree/0,
    merkle_proof/0]).

-spec delete(key(), tree()) -> tree().
%% @doc Remove key from tree. The key must be present in the tree.
delete(Key, {Size, RootNode}) ->
    {Size - 1, delete_1(Key, RootNode)}.

-spec delete_1(key(), tree_node()) -> tree_node().
delete_1(Key, {Key, _, _}) ->
    empty;
delete_1(Key, {InnerKey, _, LeftNode, RightNode}) ->
    case Key < InnerKey of
        true ->
            case delete_1(Key, LeftNode) of
                empty ->
                    RightNode;
                NewLeftNode ->
                    {InnerKey, inner_hash(node_hash(NewLeftNode), node_hash(RightNode)), NewLeftNode, RightNode}
            end;
        _ ->
            case delete_1(Key, RightNode) of
                empty ->
                    LeftNode;
                NewRightNode ->
                    {InnerKey, inner_hash(node_hash(LeftNode), node_hash(NewRightNode)), LeftNode, NewRightNode}
            end
    end.

-spec empty() -> tree().
%% @doc Return an empty tree.
empty() ->
    {0, empty}.

-spec size(tree()) -> non_neg_integer().
%% @doc Return number of elements stored in the tree.
size({Size, _}) ->
    Size.

-spec leaf_hash(key(), value()) -> hash().
leaf_hash(Key, Value) ->
    KeyHash = ?HASH(Key),
    ValueHash = ?HASH(Value),
    ?HASH(<<KeyHash/binary, ValueHash/binary>>).

-spec inner_hash(hash(), hash()) -> hash().
inner_hash(LeftHash, RightHash) ->
    ?HASH(<<LeftHash/binary, RightHash/binary>>).

-spec root_hash(tree()) -> hash() | undefined.
%% @doc Return the hash of root node.
root_hash({_, RootNode}) ->
    node_hash(RootNode).

-spec merkle_proof(key(), tree()) -> merkle_proof().
%% @doc For a given key return a proof that, along with its value, it is contained in tree.
%% Hash for root node is not included in the proof.
merkle_proof(Key, {_Size, RootNode}) ->
    merkle_proof_node(Key, RootNode).

-spec merkle_proof_node(key(), tree_node()) -> merkle_proof().
merkle_proof_node(Key, {Key, Value, _}) ->
    {?HASH(Key), ?HASH(Value)};
merkle_proof_node(Key, {InnerKey, _, Left, Right}) ->
    case Key < InnerKey of
        true ->
            {merkle_proof_node(Key, Left), node_hash(Right)};
        _ ->
            {node_hash(Left), merkle_proof_node(Key, Right)}
    end.

-spec from_list(list({key(), value()})) -> tree().
%% @doc Create a tree from a list.
%% This creates a tree by iteratively inserting elements and not necessarily results in a perfect balance, like the one obtained when running {@link from_orddict/1}.
from_list(List) ->
    from_list(List, empty()).

-spec from_list(list({key(), value()}), Acc :: tree()) -> tree().
from_list([], Acc) ->
    Acc;
from_list([{Key, Value}|Rest], Acc) ->
    from_list(Rest, enter(Key, Value, Acc)).

-spec from_orddict(OrdDict :: list({key(), value()})) -> tree().
%% @equiv from_orddict(OrdDict, length(OrdDict))
from_orddict(OrdDict) ->
    from_orddict(OrdDict, length(OrdDict)).

-spec from_orddict(list({key(), value()}), Size :: non_neg_integer()) -> tree().
%% @doc Create a perfectly balanced tree from an ordered dictionary.
from_orddict(OrdDict, Size) ->
    {Size, balance_orddict(OrdDict, Size)}.

-spec to_orddict(tree()) -> list({key(), value()}).
%% @doc Convert tree to an orddict.
to_orddict(Tree) ->
    foldr(
      fun (KV, Acc) ->
              [KV|Acc]
      end,
      [],
      Tree).

-spec foldr(fun(({key(), value()}, Acc :: any()) -> any()), Acc :: any(), tree()) -> Acc :: any().
%% @doc Iterate through keys and values, from those with highest keys to lowest.
foldr(Fun, Acc, {_, RootNode}) ->
    foldr_1(Fun, Acc, RootNode).

-spec foldr_1(fun(({key(), value()}, Acc :: any()) -> any()), Acc :: any(), tree_node()) -> Acc :: any().
foldr_1(_, Acc, empty) ->
    Acc;
foldr_1(F, Acc, _LeafNode={Key, Value, _}) ->
    F({Key, Value}, Acc);
foldr_1(F, Acc, {_, _, Left, Right}) ->
    foldr_1(F, foldr_1(F, Acc, Right), Left).

-spec node_hash(tree_node()) -> hash() | undefined.
node_hash(empty) ->
    undefined;
node_hash({_, _, Hash}) ->
    Hash;
node_hash({_, Hash, _, _}) ->
    Hash.

-spec enter(key(), value(), tree()) -> tree().
%% @doc Insert or update key and value into tree.
enter(Key, Value, {Size, RootNode}) ->
    {NewRootNode, undefined, undefined, KeyExists} = enter_1(Key, Value, RootNode, 0, Size),
    NewSize =
        case KeyExists of
            true -> Size;
            _ -> Size + 1
        end,
    {NewSize, NewRootNode}.

-spec enter_1(key(), value(), tree_node(), Depth :: non_neg_integer(), TreeSize :: non_neg_integer()) ->
                     {tree_node(), RebalancingCount :: pos_integer() | undefined, Height :: non_neg_integer() | undefined, KeyExists :: boolean()}.
enter_1(Key, Value, empty, _, _) ->
    {{Key, Value, leaf_hash(Key, Value)}, undefined, undefined, false};
enter_1(Key, Value, ExistingLeafNode={ExistingKey, _, _}, Depth, TreeSize) ->
    NewLeafNode = {Key, Value, leaf_hash(Key, Value)},
    case Key =:= ExistingKey of
        true ->
            {NewLeafNode, undefined, undefined, true};
        _ ->
            NewTreeSize = TreeSize + 1,
            NewDepth = Depth + 1,
            {InnerKey, LeftNode, RightNode} =
                case Key > ExistingKey of
                    true ->
                        {Key, ExistingLeafNode, NewLeafNode};
                    _ ->
                        {ExistingKey, NewLeafNode, ExistingLeafNode}
                end,
            case rebalancing_needed(NewTreeSize, NewDepth) of
                true ->
                    {{InnerKey, to_be_computed, LeftNode, RightNode},
                     2,
                     1,
                     false};
                _ ->
                    {{InnerKey, inner_hash(node_hash(LeftNode), node_hash(RightNode)), LeftNode, RightNode},
                     undefined,
                     undefined,
                     false}
            end
    end;
enter_1(Key, Value, InnerNode={InnerKey, _, LeftNode, RightNode}, Depth, TreeSize) ->
    NodeToFollowSymb =
        case Key < InnerKey of
            true -> left;
            _ -> right
        end,
    {NodeToFollow, NodeNotChanged} =
        case NodeToFollowSymb of
            right -> {RightNode, LeftNode};
            left -> {LeftNode, RightNode}
        end,
    {NewNode, RebalancingCount, Height, KeyExists} = enter_1(Key, Value, NodeToFollow, Depth + 1, TreeSize),
    {NewLeftNode, NewRightNode} =
        case NodeToFollowSymb of
            right ->
                {LeftNode, NewNode};
            _ ->
                {NewNode, RightNode}
        end,
    case RebalancingCount of
        undefined ->
            {update_inner_node(InnerNode, NewLeftNode, NewRightNode), undefined, undefined, KeyExists};
        _ ->
            Count = RebalancingCount + node_size(NodeNotChanged),
            NewHeight = Height + 1,
            NewInnerNodeUnbalanced = {InnerKey, to_be_computed, NewLeftNode, NewRightNode},
            case may_be_rebalanced(Count, NewHeight) of
                true ->
                    {balance_node(NewInnerNodeUnbalanced, Count),
                     undefined,
                     undefined,
                     KeyExists};
                _ ->
                    {NewInnerNodeUnbalanced,
                     Count,
                     NewHeight,
                     KeyExists}
            end
    end.

-spec rebalancing_needed(TreeSize :: non_neg_integer(), Depth :: non_neg_integer()) -> boolean().
rebalancing_needed(TreeSize, Depth) ->
    math:pow(2, Depth) > math:pow(TreeSize, ?C).

-spec may_be_rebalanced(Count :: non_neg_integer(), Height :: non_neg_integer()) -> boolean().
may_be_rebalanced(Count, Height) ->
    math:pow(2, Height) > math:pow(Count, ?C).

-spec node_size(tree_node()) -> non_neg_integer().
node_size(empty) ->
    0;
node_size({_, _, _}) ->
    1;
node_size({_, _, Left, Right}) ->
    node_size(Left) + node_size(Right).

-spec balance_orddict(list({key(), value()}), Size :: non_neg_integer()) -> tree_node().
balance_orddict(KVOrdDict, Size) ->
    {Node, []} = balance_orddict_1(KVOrdDict, Size),
    Node.

-spec balance_orddict_1(list({key(), value()}), Size :: non_neg_integer()) -> {tree_node(), list({key(), value()})}.
balance_orddict_1(OrdDict, Size) when Size > 1 ->
    Size2 = Size div 2,
    Size1 = Size - Size2,
    {LeftNode, OrdDict1=[{Key, _} | _]} = balance_orddict_1(OrdDict, Size1),
    {RightNode, OrdDict2} = balance_orddict_1(OrdDict1, Size2),
    InnerNode = {Key, inner_hash(node_hash(LeftNode), node_hash(RightNode)), LeftNode, RightNode},
    {InnerNode, OrdDict2};
balance_orddict_1([{Key, Value} | OrdDict], 1) ->
    {{Key, Value, leaf_hash(Key, Value)}, OrdDict};
balance_orddict_1(OrdDict, 0) ->
    {empty, OrdDict}.

-spec node_to_orddict(tree_node()) -> list({key(), value()}).
node_to_orddict(Node) ->
    foldr_1(
      fun (KV, Acc) ->
              [KV|Acc]
      end,
      [],
      Node).

-spec balance_node(tree_node(), Size :: non_neg_integer()) -> tree_node().
balance_node(Node, Size) ->
    KVOrdDict = node_to_orddict(Node),
    balance_orddict(KVOrdDict, Size).

-spec balance(tree()) -> tree().
%% @doc Perfectly balance a tree.
balance({Size, RootNode}) ->
    {Size, balance_orddict(node_to_orddict(RootNode), Size)}.

-spec lookup(key(), tree()) -> value() | none.
%% @doc Fetch value for key from tree.
lookup(Key, {_, RootNode}) ->
    lookup_1(Key, RootNode).

-spec lookup_1(key(), inner_node() | leaf_node()) -> value() | none.
lookup_1(Key, {Key, Value, _}) ->
    Value;
lookup_1(Key, {InnerKey, _, Left, Right}) ->
    case Key < InnerKey of
        true ->
            lookup_1(Key, Left);
        _ ->
            lookup_1(Key, Right)
    end;
lookup_1(_, _) ->
    none.

-spec update_inner_node(inner_node(), Left :: tree_node(), Right :: tree_node()) -> inner_node().
update_inner_node(Node={Key, _, Left, Right}, NewLeft, NewRight) ->
    case lists:map(fun node_hash/1, [Left, Right, NewLeft, NewRight]) of
        [LeftHash, RightHash, LeftHash, RightHash] ->
            %% Nothing changed, no need to rehash.
            Node;
        [_, _, NewLeftHash, NewRightHash] ->
            {Key, inner_hash(NewLeftHash, NewRightHash), NewLeft, NewRight}
    end.

-ifdef(TEST).
empty_test_() ->
    [?_assertEqual(0, ?MODULE:size(empty()))].

%% Types for Triq.
key() ->
    binary().
value() ->
    binary().
kv_orddict() ->
    ?LET(L, list({key(), value()}), orddict:from_list(L)).
tree() ->
    %% The validity of data generated by this generator depends on the validity of the `from_list' function.
    %% This should not be a problem as long as the `from_list' function itself is tested.
    ?LET(KVO, list({key(), value()}), from_list(KVO)).
non_empty_tree() ->
    ?SUCHTHAT(Tree, tree(), element(1, Tree) > 0).

%% Helper functions for Triq.
-spec height(tree()) -> non_neg_integer().
height({_, RootNode}) ->
    node_height(RootNode).

-spec node_height(tree_node()) -> non_neg_integer().
node_height(empty) ->
    %% Strictly speaking, there is no height for empty tree.
    0;
node_height({_, _, _}) ->
    0;
node_height({_, _, Left, Right}) ->
    1 + max(node_height(Left), node_height(Right)).

-spec shallow_height(tree()) -> non_neg_integer().
shallow_height({_, RootNode}) ->
    node_shallow_height(RootNode).

-spec node_shallow_height(tree_node()) -> non_neg_integer().
node_shallow_height(empty) ->
    %% Strictly speaking, there is no height for empty tree.
    0;
node_shallow_height({_, _, _}) ->
    0;
node_shallow_height({_, _, Left, Right}) ->
    1 + min(node_shallow_height(Left), node_shallow_height(Right)).

-spec is_perfectly_balanced(tree()) -> boolean().
is_perfectly_balanced(Tree) ->
    height(Tree) - shallow_height(Tree) =< 1.

-spec fun_idempotent(F :: fun((X) -> X), X) -> boolean().
%% @doc Return true if F(X) =:= X.
fun_idempotent(F, X) ->
    F(X) =:= X.

-spec merkle_fold(merkle_proof()) -> hash().
merkle_fold({Left, Right}) ->
    LeftHash = merkle_fold(Left),
    RightHash = merkle_fold(Right),
    ?HASH(<<LeftHash/binary, RightHash/binary>>);
merkle_fold(Hash) ->
    Hash.

-spec bottom_merkle_proof_pair(merkle_proof()) -> {hash(), hash()}.
bottom_merkle_proof_pair({Pair, Hash}) when is_tuple(Pair), is_binary(Hash) ->
    bottom_merkle_proof_pair(Pair);
bottom_merkle_proof_pair({_Hash, Pair}) when is_tuple(Pair) ->
    bottom_merkle_proof_pair(Pair);
bottom_merkle_proof_pair(Pair) ->
    Pair.

prop_lookup_does_not_fetch_deleted_key() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            none =:= lookup(Key, delete(Key, enter(Key, Value, Tree)))).
prop_deletion_decreases_size_by_1() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            ?MODULE:size(enter(Key, Value, Tree)) - 1 =:= ?MODULE:size(delete(Key, enter(Key, Value, Tree)))).
prop_merkle_proofs_fold_to_root_hash() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            root_hash(enter(Key, Value, Tree)) =:= merkle_fold(merkle_proof(Key, enter(Key, Value, Tree)))).
prop_merkle_proofs_contain_kv_hashes_at_the_bottom() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            bottom_merkle_proof_pair(merkle_proof(Key, enter(Key, Value, Tree))) =:= {?HASH(Key), ?HASH(Value)}).
prop_from_list_size() ->
    ?FORALL(KVList, list({key(), value()}),
            length(proplists:get_keys(KVList)) =:= ?MODULE:size(from_list(KVList))).
prop_from_orddict_size() ->
    ?FORALL(KVO, kv_orddict(),
            length(KVO) =:= ?MODULE:size(from_list(KVO))).
prop_orddict_conversion_idempotence() ->
    ?FORALL(KVO, kv_orddict(), KVO =:= to_orddict(from_orddict(KVO))).
prop_from_orddict_returns_a_perfectly_balanced_tree() ->
    ?FORALL(KVO, kv_orddict(), is_perfectly_balanced(from_orddict(KVO))).
from_list_sometimes_doesnt_return_a_perfectly_balanced_tree_test() ->
    ?assertNotEqual(
       true,
       triq:counterexample(
         ?FORALL(
            KVList,
            list({key(), value()}),
            is_perfectly_balanced(from_list(KVList))))).
prop_foldr_iterates_on_proper_ordering_and_contains_no_duplicates() ->
    ?FORALL(Tree, tree(),
            fun_idempotent(
              fun lists:usort/1,
              foldr(
                fun({Key, _}, Acc) -> [Key|Acc] end,
                [],
                Tree)
             )).
prop_enter_is_idempotent() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            fun_idempotent(
              fun (Tree_) -> enter(Key, Value, Tree_) end,
              enter(Key, Value, Tree))).
prop_entered_value_can_be_retrieved() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            Value =:= lookup(Key, enter(Key, Value, Tree))).
prop_entered_value_can_be_retrieved_after_balancing() ->
    ?FORALL({Tree, Key, Value},
            {tree(), key(), value()},
            Value =:= lookup(Key, balance(enter(Key, Value, Tree)))).
prop_height_constrained() ->
    ?FORALL(Tree, non_empty_tree(), math:pow(2, height(Tree)) =< math:pow(?MODULE:size(Tree), ?C)).
prop_balancing_yields_same_orddict() ->
    ?FORALL(Tree, tree(), to_orddict(Tree) =:= to_orddict(balance(Tree))).
prop_entering_key_second_time_does_not_increase_size() ->
    ?FORALL({Tree, Key, Value1, Value2},
            {tree(), key(), value(), value()},
            ?MODULE:size(enter(Key, Value1, Tree)) =:= ?MODULE:size(enter(Key, Value2, enter(Key, Value1, Tree)))).
prop_tree_after_explicit_balancing_is_perfectly_balanced() ->
    ?FORALL(Tree, tree(), is_perfectly_balanced(balance(Tree))).
-endif.
