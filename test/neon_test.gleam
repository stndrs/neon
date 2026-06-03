import gleeunit
import neon/ssl

pub fn main() -> Nil {
  assert Ok(Nil) == ssl.start()

  gleeunit.main()
}
