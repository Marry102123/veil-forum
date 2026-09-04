//! Integration tests for moderation persistence and visibility semantics.
use veil_forum::store::{Role, Store};

async fn fixture() -> anyhow::Result<(Store, i64, i64, i64)> {
    let store = Store::open(":memory:").await?;
    let alice = store.create_user("alice", "hash", false).await?;
    let bob = store.create_user("bob", "hash", false).await?;
    let board = store
        .create_board("governance", "Governance", "test board", true, true)
        .await?;
    Ok((store, board, alice, bob))
}

#[tokio::test]
async fn roles_are_idempotent_and_reversible() -> anyhow::Result<()> {
    let (store, board, alice, bob) = fixture().await?;
    assert!(!store.user_has_role(alice, Role::Moderator).await?);
    store.grant_role(alice, Role::Moderator, Some(bob)).await?;
    store.grant_role(alice, Role::Moderator, Some(bob)).await?;
    store.add_board_moderator(board, alice, Some(bob)).await?;
    assert!(store.user_has_role(alice, Role::Moderator).await?);
    assert_eq!(store.list_user_roles(alice).await?, vec![Role::Moderator]);
    assert!(store.can_moderate_board(board, alice).await?);
    store.revoke_role(alice, Role::Moderator).await?;
    assert!(!store.user_has_role(alice, Role::Moderator).await?);
    assert!(!store.can_moderate_board(board, alice).await?);
    Ok(())
}

#[tokio::test]
async fn board_moderator_scope_does_not_grant_other_boards() -> anyhow::Result<()> {
    let (store, board, alice, bob) = fixture().await?;
    let other = store
        .create_board("other", "Other", "test", true, true)
        .await?;
    store.grant_role(alice, Role::Moderator, Some(bob)).await?;
    store.add_board_moderator(board, alice, Some(bob)).await?;
    store.add_board_moderator(board, alice, Some(bob)).await?;
    assert!(store.is_board_moderator(board, alice).await?);
    assert!(store.can_moderate_board(board, alice).await?);
    assert!(!store.is_board_moderator(other, alice).await?);
    assert!(!store.can_moderate_board(other, alice).await?);
    store.remove_board_moderator(board, alice).await?;
    assert!(!store.can_moderate_board(board, alice).await?);
    Ok(())
}

#[tokio::test]
async fn reports_validate_targets_filter_and_resolve_once() -> anyhow::Result<()> {
    let (store, _board, alice, bob) = fixture().await?;
    let id = store.create_report(Some(alice), "post", 42, "spam").await?;
    store.create_report(None, "thread", 7, "abuse").await?;
    assert!(store
        .create_report(Some(alice), "comment", 1, "bad")
        .await
        .is_err());
    let open = store.list_reports(Some("open"), 50).await?;
    assert_eq!(open.len(), 2);
    assert_eq!(open[0].status, "open");
    store
        .resolve_report(id, bob, "resolved", Some("removed"))
        .await?;
    let resolved = store.list_reports(Some("resolved"), 50).await?;
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].resolved_by_user_id, Some(bob));
    assert_eq!(resolved[0].resolution_note.as_deref(), Some("removed"));
    store.resolve_report(id, alice, "dismissed", None).await?;
    assert_eq!(store.list_reports(Some("dismissed"), 50).await?.len(), 0);
    assert!(store
        .resolve_report(id, bob, "invalid", None)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn soft_delete_hides_data_but_restore_recovers_it() -> anyhow::Result<()> {
    let (store, board, alice, _bob) = fixture().await?;
    let thread = store
        .create_thread(board, alice, "hello", "body", "<p>body</p>", false)
        .await?;
    let post = store
        .create_post(thread, board, alice, false, "reply", "<p>reply</p>")
        .await?;
    assert!(store.get_post(post).await?.is_some());
    assert_eq!(store.list_threads(board, 1, 20).await?.1, 1);
    assert_eq!(store.list_posts(thread, 1, 20).await?.1, 2);

    assert!(store.soft_delete_post(post, Some(alice)).await?);
    assert!(!store.soft_delete_post(post, Some(alice)).await?);
    assert!(store.get_post(post).await?.is_none());
    assert_eq!(store.list_posts(thread, 1, 20).await?.1, 1);
    assert!(store.restore_post(post).await?);
    assert!(!store.restore_post(post).await?);
    assert!(store.get_post(post).await?.is_some());

    assert!(store.soft_delete_thread(thread, Some(alice)).await?);
    assert_eq!(store.list_threads(board, 1, 20).await?.1, 0);
    // Public thread lookup hides soft-deleted content, while the row remains
    // recoverable by the moderation lifecycle APIs.
    assert!(store.get_thread(thread).await?.is_none());
    assert!(store.restore_thread(thread).await?);
    assert_eq!(store.list_threads(board, 1, 20).await?.1, 1);
    Ok(())
}
