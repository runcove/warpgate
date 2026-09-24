use poem_openapi::OpenApiService;
use regex::Regex;
use warpgate_version::warpgate_version;
use warpgate_protocol_http::api;

#[allow(clippy::unwrap_used)]
pub fn main() {
    warpgate_version::set_warpgate_version(warpgate_version::git_describe!());
    let api_service = OpenApiService::new(api::get(), "Warpgate HTTP proxy", warpgate_version())
        .server("/@warpgate/api");

    let spec = api_service.spec();
    let re = Regex::new(r"PaginatedResponse<(?P<name>\w+)>").unwrap();
    let spec = re.replace_all(&spec, "Paginated$name");

    println!("{spec}");
}
