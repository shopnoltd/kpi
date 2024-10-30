import {useOrganizationQuery} from 'jsapp/js/account/stripe.api';
import styles from './organizationBadge.module.scss';

export default function OrganizationBadge() {
  const orgQuery = useOrganizationQuery();

  if (orgQuery.data?.is_mmo) {
    return (
      <div className={styles.root}>{orgQuery.data.name.toUpperCase()}</div>
    );
  } else {
    return null;
  }
}
