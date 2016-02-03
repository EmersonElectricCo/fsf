This page is meant to help enable folks interested in using JQ to interact with the JSON data produced by FSF.

Remove JSON Nodes
-----------------

Create the following JQ script

```
vim fsf_module_filter.jq
def post_recurse(f):
   def r:
      (f | select(. != null) | r), .;
      r;
def post_recurse:
   post_recurse(.[]?);
(post_recurse | objects) |= reduce $delete[] as $d (.; delpaths([[ $d ]]))
```

Invocation with multiple nodes with sample [Test.json](https://github.com/EmersonElectricCo/fsf/blob/master/docs/Test.json) from FSF.

```
cat Test.json | jq --argjson delete '["META_BASIC_INFO","SCAN_YARA"]' -f fsf_module_filter.jq | less
```

Show Select JSON Nodes
----------------------

Show results from only one module

```
cat Test.json | jq '..|.SCAN_YARA? | select(type != "null")'
```
