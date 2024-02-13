use askama::Template;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};

use crate::users::AuthSession;

#[derive(Template)]
#[template(path = "dashboard.html.j2")]
struct DashboardTemplate<'a> {
    title: &'static str,
    username: Option<&'a str>,
}

pub fn router() -> Router<()> {
    Router::new().route("/", get(self::get::dashboard))
}

mod get {
    use super::*;

    pub async fn dashboard(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user {
            Some(user) => DashboardTemplate {
                title: "Dashboard",
                username: Some(&user.username),
            }
            .into_response(),

            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
