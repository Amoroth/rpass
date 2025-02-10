use std::fs;
use std::io;
use std::str::FromStr;
use std::env;

#[derive(Debug)]
struct Credential {
  name: String,
  username: String,
  password: String,
}

impl FromStr for Credential {
  type Err = &'static str;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 3 {
      return Err("Invalid number of parts");
    }

    let name = parts[0].trim().to_string();
    let username = parts[1].trim().to_string();
    let password = parts[2].trim().to_string();

    Ok(Credential { name, username, password})
  }
}

fn read_store_file() -> io::Result<String> {
  // hardcoded ftw
  fs::read_to_string("/home/oskar/passwords.txt")
}

fn read_store() -> Result<Vec<Credential>, Box<dyn std::error::Error>> {
  let file_contents = match read_store_file() {
    Ok(contents) => contents,
    Err(e) => {
      eprintln!("Error reading file: {}", e);
      return Err(e.into());
    }
  };

  let lines: Vec<&str> = file_contents
    .split('\n')
    .map(|line| line.trim_end_matches('\r'))
    .collect();

  let mut credentials: Vec<Credential> = Vec::new();

  for line in lines {
    if line.is_empty() {
      continue;
    }
    match Credential::from_str(line) {
      Ok(cred) => credentials.push(cred),
      Err(e) => {
        eprintln!("Error parsing line: '{}', error: {}", line, e);
        // return Err(e.into());
      }
    }
  }

  Ok(credentials)
}

fn get_password(credentials: Vec<Credential>, name: &str) -> Result<Credential, Box<dyn std::error::Error>> {
  // seach by similarity. If found one, print it, if found multiple, ask which one you meant
  for cred in credentials {
    if cred.name == *name {
      return Ok(cred);
    }
  }

  Err(format!("Credentials for \"{}\" not found", name).into())
}

fn print_password(credentials: Vec<Credential>, name: &str) {
  match get_password(credentials, name) {
    Ok(cred) => {
      println!("Name: {}, Username: {}, Password: {}", cred.name, cred.username, cred.password);
      return;
    },
    Err(_) => println!("Credentials for \"{}\" not found", name)
  }
}

fn print_all_passwords(credentials: Vec<Credential>) {
  for cred in credentials {
    println!("Name: {}", cred.name);
  }
}

fn main() {
  let args: Vec<String> = env::args().collect();

  let search_name: Option<&String> = args.get(1);

  let credentials = match read_store() {
    Ok(s) => s,
    Err(e) => {
      eprintln!("An error occurred: {}", e);
      return;
    }
  };

  match search_name {
    Some(name) => {
      print_password(credentials, name);
      return;
    },
    None => {
      print_all_passwords(credentials);
      return;
    }
  }
}
