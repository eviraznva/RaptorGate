use proc_macro::TokenStream;
use syn::Fields;
use syn::parse::ParseStream;
use quote::quote;
use syn::Data;
use syn::Token;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(Validate, attributes(foreign_key))]
#[allow(clippy::missing_panics_doc)]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let fields = match &input.data {
        Data::Struct(s) => &s.fields,
        _ => panic!("Validate only supports structs"),
    };

    let foreign_keys: Vec<_> = match fields {
        Fields::Named(fields) => fields.named.iter().filter_map(|field| {
            let fk_attr = field.attrs.iter().find(|a| a.path().is_ident("foreign_key"))?;
            let field_name = field.ident.as_ref().unwrap();

            let provider_type: syn::Path = fk_attr.parse_args_with(|input: ParseStream| {
                let _: syn::Ident = input.parse()?; // "provider"
                let _: Token![=] = input.parse()?;
                input.parse()
            }).expect("expected #[foreign_key(provider = SomeProvider)]");

            Some((field_name, provider_type))
        }).collect(),
        _ => panic!("Validate only supports named fields"),
    };

    // One where clause bound per foreign key: Ctx: HasProvider<ProviderType>
    let bounds = foreign_keys.iter().map(|(_, provider_type)| {
        quote! { Ctx: HasProvider<#provider_type> }
    });

    // One check per foreign key using UFCS to avoid ambiguity
    let checks = foreign_keys.iter().map(|(field_name, provider_type)| {
        let relation = format!(
            "{}.{} -> {}",
            struct_name,
            field_name,
            quote!(#provider_type)
        );

        quote! {
            <Ctx as HasProvider<#provider_type>>::get_provider(ctx)
                .get_item(&self.#field_name)
                .ok_or(IntegrityError::DanglingReference {
                    fk: self.#field_name.to_string(),
                    relation: #relation,
                })?;
        }
    });

    quote! {
        impl<Ctx> Validate<Ctx> for #struct_name
        where
            #(#bounds),*
        {
            fn validate(&self, ctx: &Ctx) -> Result<(), IntegrityError> {
                #(#checks)*
                Ok(())
            }
        }
    }.into()
}
