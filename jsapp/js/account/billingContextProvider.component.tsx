import React, {ReactNode} from 'react';
import { OneTimeAddOnsContext, useOneTimeAddOns } from './useOneTimeAddonList.hook';
import {UsageContext, useUsage} from 'js/account/usage/useUsage.hook';
import {ProductsContext, useProducts} from 'js/account/useProducts.hook';
import {
  OrganizationContext,
  useOrganization,
} from 'js/account/organizations/useOrganization.hook';
import sessionStore from 'js/stores/session';

export const BillingContextProvider = (props: {children: ReactNode}) => {
  if (!sessionStore.isLoggedIn) {
    return <>{props.children}</>;
  }
  const [organization, reloadOrg, orgStatus] = useOrganization();
  const oneTimeAddOns = useOneTimeAddOns();
  const usage = useUsage(organization?.id);
  const products = useProducts();
  return (
    <OrganizationContext.Provider value={[organization, reloadOrg, orgStatus]}>
      <UsageContext.Provider value={usage}>
        <ProductsContext.Provider value={products}>
          <OneTimeAddOnsContext.Provider value={oneTimeAddOns}>
            {props.children}
          </OneTimeAddOnsContext.Provider>
        </ProductsContext.Provider>
      </UsageContext.Provider>
    </OrganizationContext.Provider>
  );
};
