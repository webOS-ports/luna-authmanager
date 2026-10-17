// A std::string built from json_object_get_string() of a field looked up in
// the same expression: a missing key (or a JSON null) gives NULL, and a
// std::string constructed or assigned from NULL is undefined behaviour.
@@
expression R, K;
identifier s;
@@
(
* std::string s = json_object_get_string(json_object_object_get(R, K));
|
* s = json_object_get_string(json_object_object_get(R, K));
)
