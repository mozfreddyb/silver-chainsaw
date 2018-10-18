

fn typefromid(id: u8) -> String {
    let policytypes = include!("policytypes.in");
    policytypes[id]
}
