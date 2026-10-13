//! Bounded authentication eligibility scripts; no credential or grant authority.
use mlua::{HookTriggers, Lua, LuaOptions, StdLib, Value, VmState, chunk::ChunkMode};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

const SOURCE_LIMIT: usize = 16 * 1024;
const MEMORY_LIMIT: usize = 256 * 1024;
const HOOK_INTERVAL: u32 = 100;
const HOOK_LIMIT: u32 = 200;
const TIME_LIMIT: Duration = Duration::from_millis(5);

#[derive(Clone)]
pub struct Policy(Arc<str>);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

pub struct Context<'a> {
    pub service: &'a str,
    pub connector: &'a str,
    pub subject: &'a str,
}

fn machine() -> Result<Lua, Refused> {
    let lua = Lua::new_with(StdLib::NONE, LuaOptions::default()).map_err(|_| Refused)?;
    lua.set_memory_limit(MEMORY_LIMIT).map_err(|_| Refused)?;
    Ok(lua)
}

impl Policy {
    pub fn compile(source: &str) -> Result<Self, Refused> {
        if source.is_empty() || source.len() > SOURCE_LIMIT || source.as_bytes().contains(&0) {
            return Err(Refused);
        }
        let lua = machine()?;
        lua.load(source)
            .set_mode(ChunkMode::Text)
            .into_function()
            .map_err(|_| Refused)?;
        Ok(Self(Arc::from(source)))
    }

    /// `true` only permits the native connector to continue. It never verifies
    /// credentials, constructs evidence, assigns AAL or bypasses owner commits.
    pub fn permits(&self, context: Context<'_>) -> Result<bool, Refused> {
        if [context.service, context.connector, context.subject]
            .iter()
            .any(|value| value.is_empty() || value.len() > 256)
        {
            return Err(Refused);
        }
        let started = Instant::now();
        let lua = machine()?;
        let ticks = Arc::new(AtomicU32::new(0));
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(HOOK_INTERVAL),
            move |_, _| {
                if ticks.fetch_add(1, Ordering::Relaxed) >= HOOK_LIMIT
                    || started.elapsed() > TIME_LIMIT
                {
                    return Err(mlua::Error::RuntimeError(
                        "authentication script budget exceeded".into(),
                    ));
                }
                Ok(VmState::Continue)
            },
        )
        .map_err(|_| Refused)?;
        // Replace the environment entirely. In particular, pcall/xpcall cannot
        // catch the budget hook, and load/debug/coroutine/IO are unavailable.
        let environment = lua.create_table().map_err(|_| Refused)?;
        let values = lua.create_table().map_err(|_| Refused)?;
        for (key, value) in [
            ("service", context.service),
            ("connector", context.connector),
            ("subject", context.subject),
        ] {
            values.set(key, value).map_err(|_| Refused)?;
        }
        environment.set("context", values).map_err(|_| Refused)?;
        let value: Value = lua
            .load(self.0.as_ref())
            .set_mode(ChunkMode::Text)
            .set_environment(environment)
            .eval()
            .map_err(|_| Refused)?;
        if started.elapsed() > TIME_LIMIT {
            return Err(Refused);
        }
        match value {
            Value::Boolean(value) => Ok(value),
            _ => Err(Refused),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context<'static> {
        Context {
            service: "payroll",
            connector: "organization",
            subject: "owned-user",
        }
    }
    #[test]
    fn typed_eligibility_and_environment_isolation() {
        assert_eq!(
            Policy::compile("return context.service == 'payroll'")
                .unwrap()
                .permits(context()),
            Ok(true)
        );
        assert_eq!(
            Policy::compile("return context.service == 'public'")
                .unwrap()
                .permits(context()),
            Ok(false)
        );
        for script in [
            "return 1",
            "return 'true'",
            "return {}",
            "return os.getenv('SECRET')",
            "return io.open('/etc/passwd')",
            "return load('return true')()",
            "return pcall(function() return true end)",
            "return debug.getregistry()",
            "return coroutine.create(function() end)",
            "return ('x'):rep(100)",
        ] {
            assert_eq!(
                Policy::compile(script).unwrap().permits(context()),
                Err(Refused)
            );
        }
        assert_eq!(
            Policy::compile("context.service='changed'; return true")
                .unwrap()
                .permits(context()),
            Ok(true)
        );
        assert_eq!(
            Policy::compile("return context.service == 'payroll'")
                .unwrap()
                .permits(context()),
            Ok(true)
        );
    }
    #[test]
    fn hostile_execution_and_compilation_are_bounded() {
        for script in [
            "while true do end",
            "local t={}; for i=1,1000000 do t[i]=i end; return true",
            "local function f() return 1+f() end; return f()",
        ] {
            let started = Instant::now();
            assert_eq!(
                Policy::compile(script).unwrap().permits(context()),
                Err(Refused)
            );
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        for source in [
            "".to_owned(),
            "return (".to_owned(),
            "x".repeat(SOURCE_LIMIT + 1),
            "\x1bLua".to_owned(),
        ] {
            assert!(Policy::compile(&source).is_err());
        }
    }
}
