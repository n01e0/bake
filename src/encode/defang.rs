pub fn encode(input: &str) -> String {
    input.replace(".", "[.]").replace(":", "[:]")
}
