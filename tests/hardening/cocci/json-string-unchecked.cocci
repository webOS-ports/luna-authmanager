// json_object_object_get() returns NULL for a missing key (and for a JSON
// null), json_object_get_string() passes the NULL on, and the str*cmp family
// dereferences it: a bus payload that leaves the field out crashes the
// daemon. Flags a field looked up and compared in one expression, with no
// chance for a NULL check in between.
@@
expression R, K, S, N;
@@
(
* strcmp(json_object_get_string(json_object_object_get(R, K)), S)
|
* strcmp(S, json_object_get_string(json_object_object_get(R, K)))
|
* strncmp(json_object_get_string(json_object_object_get(R, K)), S, N)
|
* strcasecmp(json_object_get_string(json_object_object_get(R, K)), S)
)
