use crate::fingerprint::Fingerprints;

pub fn fingerprints(file: &String) -> Vec<Fingerprints> {
    let contents = std::fs::read_to_string(file).expect("Something went wrong reading the file");

    return Vec::new();
}

pub fn is_json(output: String) -> bool {
    if output.contains(".json") {
        if &output[output.len() - 5..] == ".json" {
            return true;
        }
    }

    false
}
