//! Build-time bridge for embedding the generated canonical OpenAPI document.

pub const bytes = @embedFile("generated/openapi.json");
