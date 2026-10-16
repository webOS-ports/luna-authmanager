// A g_strdup_printf() handed straight to another call is never freed: the
// pattern that leaked the location request's parameters.
@@
identifier f !~ "^(g_free|free|g_string_append|g_string_new|g_strdup)$";
expression list A, B;
@@
* f(A, g_strdup_printf(...), B)
