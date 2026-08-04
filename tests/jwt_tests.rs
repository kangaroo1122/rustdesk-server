use hbb_common::tokio;
use hbbs::jwt;

#[test]
fn test_generate_token() {
    std::env::set_var("RUSTDESK_API_JWT_KEY", "testjwt");
    let token = jwt::generate_token(1, 3600).unwrap();
    println!("Generated Token: {}", token);
    assert!(!token.is_empty(), "Generated token should not be empty");
}

#[tokio::test]
async fn test_verify_token() {
    std::env::set_var("RUSTDESK_API_JWT_KEY", "testjwt");
    let token = jwt::generate_token(1, 2).unwrap();
    // let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3MzY4NzA4NjF9.u5pxmwNMrYUwtkspF1FuZj-R5ANAR9WT9_dMHuQhV0Y";
    println!(
        "Token : {:?}, now: {:?}",
        token,
        chrono::Utc::now().timestamp()
    );

    // hbb_common::sleep(3f32).await;
    // println!("Token : {:?}, now: {:?}", token, chrono::Utc::now().timestamp());
    let result = jwt::verify_token(&token);
    println!("Token Verification Result: {:?}", result);
    assert!(result.is_ok(), "Token should be valid");
}
