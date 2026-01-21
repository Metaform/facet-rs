//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

/// Helper to create a PostgreSQL container and connection pool
pub async fn setup_postgres_container() -> (PgPool, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .unwrap();

    let connection_string = format!(
        "postgresql://postgres:postgres@127.0.0.1:{}/postgres",
        container.get_host_port_ipv4(5432).await.unwrap()
    );

    // Wait for PostgreSQL to be ready with timeout
    let pool = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        async {
            loop {
                match PgPool::connect(&connection_string).await {
                    Ok(pool) => break pool,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        }
    )
    .await
    .unwrap_or_else(|_| panic!("PostgreSQL failed to become ready within 5 seconds"));

    (pool, container)
}
