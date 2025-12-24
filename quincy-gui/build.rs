fn main() {
    #[cfg(windows)]
    {
        // Set icon for all binaries
        let mut res = winresource::WindowsResource::new();
        res.set_icon("resources/icon.ico");
        res.compile().unwrap();

        // Embed UAC manifest only for the daemon binary
        let _ = embed_resource::compile_for(
            "resources/quincy-client-daemon.rc",
            ["quincy-client-daemon"],
            embed_resource::NONE,
        );
    }
}
