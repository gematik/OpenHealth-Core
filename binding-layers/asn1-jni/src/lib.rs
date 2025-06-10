use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use asn1::{Asn1UtcTime, Asn1GeneralizedTime};

#[no_mangle]
pub extern "system" fn Java_de_gematik_openhealth_asn1_Asn1GeneralizedTime_parse(
    mut env: JNIEnv,
    _class: JClass,
    input: JString,
) -> jstring {
    let input: String = env
        .get_string(&input)
        .expect("Couldn't get java string!")
        .into();

    match Asn1GeneralizedTime::parse(&input) {
        Ok(time) => env.new_string(format!("{:?}", time))
            .expect("Couldn't create java string!")
            .into_raw(),
        Err(e) => {
            // Werfen einer IllegalArgumentException
            let exception_class = env.find_class("java/lang/IllegalArgumentException")
                .expect("Couldn't find IllegalArgumentException class");
            env.throw_new(exception_class, e)
                .expect("Couldn't throw exception");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_de_gematik_openhealth_asn1_Asn1UtcTime_parse(
    mut env: JNIEnv,
    _class: JClass,
    input: JString,
) -> jstring {
    let input: String = env
        .get_string(&input)
        .expect("Couldn't get java string!")
        .into();

    match Asn1UtcTime::parse(&input) {
        Ok(time) => env.new_string(time.format())
            .expect("Couldn't create java string!")
            .into_raw(),
        Err(e) => {
            // Werfen einer IllegalArgumentException
            let exception_class = env.find_class("java/lang/IllegalArgumentException")
                .expect("Couldn't find IllegalArgumentException class");
            env.throw_new(exception_class, e)
                .expect("Couldn't throw exception");
            std::ptr::null_mut()
        }
    }
}