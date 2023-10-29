use std::fmt;
use std::str::FromStr;

use elements::hex::{FromHex, ToHex};
use elements_miniscript as miniscript;
use miniscript::elements;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Serde<A>(pub A);

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(rename = "scriptSig")]
    pub script_sig: elements::Script,
    pub witness: Vec<Serde<Vec<u8>>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Flag {
    P2SH,
    DerSig,
    NullDummy,
    CheckLockTimeVerify,
    CheckSequenceVerify,
    Witness,
    Taproot,
    Simplicity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestCase {
    pub tx: Serde<elements::Transaction>,
    pub prevouts: Vec<Serde<elements::TxOut>>,
    pub index: usize,
    #[serde(serialize_with = "serialize_flags")]
    #[serde(deserialize_with = "deserialize_flags")]
    pub flags: Vec<Flag>,
    pub comment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_genesis_block: Option<elements::BlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<Parameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Parameters>,
    #[serde(rename = "final", skip_serializing_if = "std::ops::Not::not", default)]
    pub is_final: bool,
}

impl Parameters {
    pub fn taproot(
        script_input: Vec<u8>,
        script: elements::Script,
        control_block: elements::taproot::ControlBlock,
    ) -> Self {
        Self {
            script_sig: elements::Script::new(),
            witness: vec![
                Serde(script_input),
                Serde(script.into_bytes()),
                Serde(control_block.serialize()),
            ],
        }
    }
}

impl Flag {
    pub const fn all_flags() -> [Self; 8] {
        [
            Flag::P2SH,
            Flag::DerSig,
            Flag::NullDummy,
            Flag::CheckLockTimeVerify,
            Flag::CheckSequenceVerify,
            Flag::Witness,
            Flag::Taproot,
            Flag::Simplicity,
        ]
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flag::P2SH => f.write_str("P2SH"),
            Flag::DerSig => f.write_str("DERSIG"),
            Flag::NullDummy => f.write_str("NULLDUMMY"),
            Flag::CheckLockTimeVerify => f.write_str("CHECKLOCKTIMEVERIFY"),
            Flag::CheckSequenceVerify => f.write_str("CHECKSEQUENCEVERIFY"),
            Flag::Witness => f.write_str("WITNESS"),
            Flag::Taproot => f.write_str("TAPROOT"),
            Flag::Simplicity => f.write_str("SIMPLICITY"),
        }
    }
}

impl FromStr for Flag {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P2SH" => Ok(Flag::P2SH),
            "DERSIG" => Ok(Flag::DerSig),
            "NULLDUMMY" => Ok(Flag::NullDummy),
            "CHECKLOCKTIMEVERIFY" => Ok(Flag::CheckLockTimeVerify),
            "CHECKSEQUENCEVERIFY" => Ok(Flag::CheckSequenceVerify),
            "WITNESS" => Ok(Flag::Witness),
            "TAPROOT" => Ok(Flag::Taproot),
            "SIMPLICITY" => Ok(Flag::Simplicity),
            _ => Err("unknown flag"),
        }
    }
}

impl<A: elements::pset::serialize::Serialize> Serialize for Serde<A> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.serialize();
        serializer.serialize_str(&bytes.to_hex())
    }
}

impl<'de, A: elements::pset::serialize::Deserialize> Deserialize<'de> for Serde<A> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = Deserialize::deserialize(deserializer)?;
        let bytes = Vec::<u8>::from_hex(&hex).map_err(D::Error::custom)?;
        let inner = A::deserialize(&bytes).map_err(D::Error::custom)?;
        Ok(Serde(inner))
    }
}

fn serialize_flags<S>(flags: &[Flag], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = flags
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<String>>()
        .join(",");
    serializer.serialize_str(&s)
}

fn deserialize_flags<'de, D>(deserializer: D) -> Result<Vec<Flag>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.split(',')
        .map(Flag::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn serialize_roundtrip() {
        let txout = elements::TxOut::default();
        let tx = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![txout.clone(), txout],
        };
        let parameters = Parameters {
            script_sig: elements::Script::from(vec![0xca, 0xfe, 0xba, 0xbe]),
            witness: vec![Serde(vec![0xde, 0xad, 0xbe, 0xef])],
        };
        let mut test_case = TestCase {
            tx: Serde(tx.clone()),
            prevouts: vec![Serde(tx.output[0].clone()), Serde(tx.output[1].clone())],
            index: 0,
            flags: Flag::all_flags().to_vec(),
            comment: "my awesome comment".to_string(),
            hash_genesis_block: None,
            success: None,
            failure: Some(parameters.clone()),
            is_final: true,
        };

        let s = serde_json::to_string(&test_case).expect("serialize");
        let original: TestCase = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(test_case, original);

        test_case.is_final = false;
        let s = serde_json::to_string(&test_case).expect("serialize");
        let original: TestCase = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(test_case, original);
    }

    #[test]
    fn deserialize_single() {
        let s = r#"{
        "tx": "0100000000017411650fe7800c4b1c695776d7fb70e075e6f2bc235bbdd40aa800f62eced1cab700000000a0179c490101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000004a936f000064000000",
        "prevouts": ["01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000004a936f00225d20a9d25cf32bfcac56e2caef97256424dd77dd23f732614d52219bad14d86974af"],
        "index": 0,
        "flags": "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT",
        "comment": "applic/keypath",
        "hash_genesis_block": "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f",
        "success": {
            "scriptSig": "",
            "witness": [
                "4facb94910cb2ec9572d39f764aaed25ec596fd49bd688bb4833a48e51c4488903ef6053513b75f03b395f2127d4976471851afaddaf9bf55e820208b1ee9861"
            ]
        }}"#;
        let _: TestCase = serde_json::from_str(s).expect("deserialize");
    }

    #[test]
    fn deserialize_file() {
        let mut file = File::open("data/script_assets_test.json").expect("Unable to open file");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Unable to read file");

        let data: Vec<TestCase> = serde_json::from_str(&contents).expect("Unable to parse JSON");
        assert_eq!(250, data.len());
    }
}
