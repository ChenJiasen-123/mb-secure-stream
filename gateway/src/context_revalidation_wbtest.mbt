///|
test "revalidation clears expired authenticated identity" {
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = @mb_jwt.sign(
    "{\"sub\":\"alice\",\"role\":\"admin\",\"exp\":2000}", key,
  ).unwrap()
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000L)
  assert_true(ctx.is_allowed)
  execute_security_filter(ctx, key, 2000L)
  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_sub, "")
  assert_eq(ctx.user_role, "")
}

///|
test "revalidation clears failed signature and recovers cleanly" {
  let key = @mb_jwt.JwtKey::HS256("test-secret")
  let token = @mb_jwt.sign(
    "{\"sub\":\"alice\",\"role\":\"admin\",\"exp\":2000}", key,
  ).unwrap()
  let ctx = new_stream_context(token)
  execute_security_filter(ctx, key, 1000L)
  execute_security_filter(ctx, @mb_jwt.JwtKey::HS256("wrong-secret"), 1000L)
  assert_false(ctx.is_allowed)
  assert_eq(ctx.user_sub, "")
  assert_eq(ctx.user_role, "")
  assert_true(ctx.error_message != "")
  execute_security_filter(ctx, key, 1000L)
  assert_true(ctx.is_allowed)
  assert_eq(ctx.user_sub, "alice")
  assert_eq(ctx.user_role, "admin")
  assert_eq(ctx.error_message, "")
}
