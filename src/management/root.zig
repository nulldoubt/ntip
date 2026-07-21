//! Management-plane application and transport foundations.

pub const auth = @import("auth.zig");
pub const security_policy = @import("security_policy.zig");
pub const settings = @import("settings.zig");
pub const api_config = @import("api_config.zig");
pub const errors = @import("error.zig");
pub const error_contract = errors;
pub const service_ipc = @import("service_ipc.zig");
pub const service_server = @import("service_server.zig");
pub const http = @import("http.zig");
pub const api_server = @import("api_server.zig");
pub const operator_service = @import("operator_service.zig");
pub const server_application = @import("server_application.zig");
pub const inventory_service = @import("inventory_service.zig");
pub const api_response = @import("api_response.zig");
pub const api_request = @import("api_request.zig");
pub const auth_application = @import("auth_application.zig");
pub const api_application = @import("api_application.zig");
pub const operations_service = @import("operations_service.zig");
pub const operations_api = @import("operations_api.zig");
pub const enrollment_service = @import("enrollment_service.zig");
pub const bootstrap_assets = @import("bootstrap_assets.zig");
pub const bootstrap_service = @import("bootstrap_service.zig");
pub const read_models_service = @import("read_models_service.zig");

test {
    _ = auth;
    _ = security_policy;
    _ = settings;
    _ = api_config;
    _ = error_contract;
    _ = service_ipc;
    _ = service_server;
    _ = http;
    _ = api_server;
    _ = operator_service;
    _ = server_application;
    _ = inventory_service;
    _ = api_response;
    _ = api_request;
    _ = auth_application;
    _ = api_application;
    _ = operations_service;
    _ = operations_api;
    _ = enrollment_service;
    _ = bootstrap_assets;
    _ = bootstrap_service;
    _ = read_models_service;
    _ = @import("http_integration_test.zig");
}
