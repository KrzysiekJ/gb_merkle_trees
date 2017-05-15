# gb_merkle_trees

An Erlang library that provides a dictionary-like storage for binaries using general balanced binary Merkle trees, with an interface similar to `gb_trees`.

This library uses [semantic versioning 2.0](http://semver.org/). If a change causes different root hashes to be generated for the same input data when entering or deleting, it is considered backwards incompatible.

[erlang.mk](https://erlang.mk/) is used as a build tool.

## Documentation

Run `make edoc` and open `doc/index.html`.

## Contributing

Unless you’re deleting code or making pure optimizations, write tests. Except for basic cases, testing of this library is done using [triq](https://github.com/triqng/triq). To run tests, execute `make tests`.

Write function specifications. To run Dialyzer, execute `make dialyze`.

No hard line length limit is imposed.

## License

This software is licensed under under [the Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) (the “License”); you may not use this software except in compliance with the License. Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.
