use askama::Template;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
use axum_login::permission_required;

use crate::users::{AuthSession, Backend};

#[derive(Template)]
#[template(path = "restricted.html.j2")]
struct RestrictedTemplate<'a> {
    title: &'static str,
    username: Option<&'a str>,
}

pub fn router() -> Router<()> {
    Router::new().route(
        "/restricted",
        get(self::get::restricted)
            .route_layer(permission_required!(
                Backend,
                login_url = "/login",
                "restricted.read",
            ))
            .route_layer(permission_required!(
                Backend,
                login_url = "/login",
                "dashboard.read",
            )),
    )
}

mod get {
    use super::*;

    pub async fn restricted(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user {
            Some(user) => RestrictedTemplate {
                title: "Restricted",
                username: Some(&user.username),
            }
            .into_response(),

            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
