//! Proc macro for generating error types with FlatError trait implementation.
//!
//! This is a simplified version of bitwarden-error-macro that only supports
//! the `flat` error type for CLI use.

use darling::{FromMeta, ast::NestedMeta};
use quote::quote;
use syn::Data;

/// Arguments for the ap_error macro
#[derive(FromMeta)]
struct ApErrorArgs {
    #[darling(flatten)]
    #[allow(dead_code)]
    error_type: ApErrorType,
}

#[derive(FromMeta)]
#[darling(rename_all = "snake_case")]
enum ApErrorType {
    /// The error is converted into a flat error using the `FlatError` trait
    Flat,
}

/// A procedural macro for generating error types with FlatError trait implementation.
///
/// # Example
///
/// ```rust,ignore
/// use ap_error::ap_error;
/// use thiserror::Error;
///
/// #[derive(Debug, Error)]
/// #[ap_error(flat)]
/// enum MyError {
///     #[error("Not found")]
///     NotFound,
///     #[error("Permission denied")]
///     PermissionDenied,
/// }
/// ```
#[proc_macro_attribute]
pub fn ap_error(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(v) => v,
        Err(e) => {
            return proc_macro::TokenStream::from(darling::Error::from(e).write_errors());
        }
    };

    let _args = match ApErrorArgs::from_list(&attr_args) {
        Ok(params) => params,
        Err(error) => {
            return proc_macro::TokenStream::from(error.write_errors());
        }
    };

    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    // Only flat mode is supported
    ap_error_flat(&input, type_identifier)
}

fn ap_error_flat(
    input: &syn::DeriveInput,
    type_identifier: &proc_macro2::Ident,
) -> proc_macro::TokenStream {
    match &input.data {
        Data::Enum(data) => {
            let match_arms = data.variants.iter().map(|variant| {
                let variant_ident = &variant.ident;
                let variant_str = variant_ident.to_string();

                match variant.fields {
                    syn::Fields::Unit => {
                        quote! {
                            #type_identifier::#variant_ident => #variant_str
                        }
                    }
                    syn::Fields::Named(_) => {
                        quote! {
                            #type_identifier::#variant_ident { .. } => #variant_str
                        }
                    }
                    syn::Fields::Unnamed(_) => {
                        quote! {
                            #type_identifier::#variant_ident(..) => #variant_str
                        }
                    }
                }
            });

            quote! {
                #input

                #[automatically_derived]
                impl ::ap_error::flat_error::FlatError for #type_identifier {
                    fn error_variant(&self) -> &'static str {
                        match &self {
                            #(#match_arms), *
                        }
                    }
                }
            }
            .into()
        }
        _ => syn::Error::new_spanned(input, "ap_error can only be used with enums")
            .to_compile_error()
            .into(),
    }
}
