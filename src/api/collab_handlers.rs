use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use crate::collaboration::{Team, TeamRole, User, ScanShare, SharePermission};

#[derive(Clone)]
pub struct CollabState {
    pub teams: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Team>>>,
    pub users: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, User>>>,
    pub shares: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, ScanShare>>>,
}

impl CollabState {
    pub fn new() -> Self {
        Self {
            teams: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            users: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            shares: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}

pub async fn create_team(
    State(state): State<CollabState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = payload["name"].as_str().unwrap_or("Unnamed Team");
    let owner_id = payload["owner_id"].as_str().unwrap_or("unknown");

    let team = Team::new(name.to_string(), owner_id.to_string());
    let team_id = team.id.clone();

    let mut teams = state.teams.write().await;
    teams.insert(team_id.clone(), team);

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "created",
            "team_id": team_id
        })),
    )
}

pub async fn get_team(
    State(state): State<CollabState>,
    Path(team_id): Path<String>,
) -> impl IntoResponse {
    let teams = state.teams.read().await;

    match teams.get(&team_id) {
        Some(team) => (
            StatusCode::OK,
            Json(json!({
                "id": team.id,
                "name": team.name,
                "member_count": team.member_count()
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Team not found"})),
        ),
    }
}

pub async fn add_team_member(
    State(state): State<CollabState>,
    Path((team_id, user_id)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let role_str = payload["role"].as_str().unwrap_or("Member");
    let role = match role_str {
        "Owner" => TeamRole::Owner,
        "Admin" => TeamRole::Admin,
        "Member" => TeamRole::Member,
        _ => TeamRole::Viewer,
    };

    let mut teams = state.teams.write().await;

    if let Some(team) = teams.get_mut(&team_id) {
        if team.add_member(user_id.clone(), role) {
            (
                StatusCode::OK,
                Json(json!({
                    "status": "member_added",
                    "user_id": user_id
                })),
            )
        } else {
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "Member already exists"})),
            )
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Team not found"})),
        )
    }
}

pub async fn remove_team_member(
    State(state): State<CollabState>,
    Path((team_id, user_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut teams = state.teams.write().await;

    if let Some(team) = teams.get_mut(&team_id) {
        if team.remove_member(&user_id) {
            (
                StatusCode::OK,
                Json(json!({
                    "status": "member_removed",
                    "user_id": user_id
                })),
            )
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Team not found"})),
        )
    }
}

pub async fn create_user(
    State(state): State<CollabState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let username = payload["username"].as_str().unwrap_or("unknown");
    let email = payload["email"].as_str().unwrap_or("unknown@example.com");

    let user = User::new(username.to_string(), email.to_string());
    let user_id = user.id.clone();

    let mut users = state.users.write().await;
    users.insert(user_id.clone(), user);

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "created",
            "user_id": user_id
        })),
    )
}

pub async fn share_scan(
    State(state): State<CollabState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let scan_id = payload["scan_id"].as_str().unwrap_or("");
    let shared_by = payload["shared_by"].as_str().unwrap_or("");
    let shared_with = payload["shared_with"].as_str().unwrap_or("");
    let permission_str = payload["permission"].as_str().unwrap_or("View");

    let permission = match permission_str {
        "View" => SharePermission::View,
        "Comment" => SharePermission::Comment,
        "Edit" => SharePermission::Edit,
        "Share" => SharePermission::Share,
        "Download" => SharePermission::Download,
        _ => SharePermission::View,
    };

    let share = ScanShare::new(
        scan_id.to_string(),
        shared_by.to_string(),
        shared_with.to_string(),
        permission,
    );

    let share_id = share.id.clone();

    let mut shares = state.shares.write().await;
    shares.insert(share_id.clone(), share);

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "shared",
            "share_id": share_id
        })),
    )
}

pub async fn get_shares(
    State(state): State<CollabState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let shares = state.shares.read().await;

    let user_shares: Vec<_> = shares
        .values()
        .filter(|s| s.shared_with == user_id && s.is_active)
        .map(|s| {
            json!({
                "id": s.id,
                "scan_id": s.scan_id,
                "permission": format!("{:?}", s.permission)
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "shares": user_shares
        })),
    )
}

pub async fn revoke_share(
    State(state): State<CollabState>,
    Path(share_id): Path<String>,
) -> impl IntoResponse {
    let mut shares = state.shares.write().await;

    if let Some(share) = shares.get_mut(&share_id) {
        share.is_active = false;
        (
            StatusCode::OK,
            Json(json!({
                "status": "revoked",
                "share_id": share_id
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Share not found"})),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        let state = CollabState::new();
        assert!(state.teams.try_read().is_ok());
        assert!(state.users.try_read().is_ok());
    }
}
