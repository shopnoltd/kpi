import {fetchGet} from 'jsapp/js/api';
import {getOrganization} from 'js/account/stripe.api';

export interface AssetUsage {
  count: string;
  next: string | null;
  previous: string | null;
  results: Asset[];
}

interface Asset {
  asset: string;
  uid: string;
  asset__name: string;
  nlp_usage_current_month: {
    total_nlp_asr_seconds: number;
    total_nlp_mt_characters: number;
  };
  nlp_usage_all_time: {
    total_nlp_asr_seconds: number;
    total_nlp_mt_characters: number;
  };
  storage_bytes: number;
  submission_count_current_month: number;
  submission_count_all_time: number;
  deployment_status: string;
}

export interface UsageResponse {
  current_month_start: string;
  current_year_start: string;
  billing_period_end: string | null;
  total_submission_count: {
    current_month: number;
    current_year: number;
    all_time: number;
  };
  total_storage_bytes: number;
  total_nlp_usage: {
    asr_seconds_current_month: number;
    mt_characters_current_month: number;
    asr_seconds_current_year: number;
    mt_characters_current_year: number;
    asr_seconds_all_time: number;
    mt_characters_all_time: number;
  };
}

const USAGE_URL = '/api/v2/service_usage/';
const ORGANIZATION_USAGE_URL =
  '/api/v2/organizations/##ORGANIZATION_ID##/service_usage/';

const ASSET_USAGE_URL = '/api/v2/asset_usage/';
const ORGANIZATION_ASSET_USAGE_URL =
  '/api/v2/organizations/##ORGANIZATION_ID##/asset_usage/';

export async function getUsage(organization_id: string | null = null) {
  if (organization_id) {
    return fetchGet<UsageResponse>(
      ORGANIZATION_USAGE_URL.replace('##ORGANIZATION_ID##', organization_id),
      {
        includeHeaders: true,
        errorMessageDisplay: t('There was an error fetching usage data.'),
      }
    );
  }
  return fetchGet<UsageResponse>(USAGE_URL, {
    includeHeaders: true,
    errorMessageDisplay: t('There was an error fetching usage data.'),
  });
}

export async function getUsageForOrganization() {
  let organizations;
  try {
    organizations = await getOrganization();
  } catch (error) {
    // if we can't get the organizations, just get usage for the current user
    return await getUsage();
  }

  return await getUsage(organizations.results?.[0].id);
}

export async function getAssetUsage(url?: string) {
  try {
    const apiUrl = url || ASSET_USAGE_URL;
    return fetchGet<AssetUsage>(apiUrl, {
      includeHeaders: true,
      errorMessageDisplay: t('There was an error fetching asset usage data.'),
    });
  } catch (error) {
    console.error('Error fetching data:', error);
    throw error;
  }
}

export async function getAssetUsageForOrganization(url?: string) {
  let organizations;
  try {
    organizations = await getOrganization();
  } catch (error) {
    return await getAssetUsage(url);
  }

  const apiUrl = url || ORGANIZATION_ASSET_USAGE_URL.replace(
    '##ORGANIZATION_ID##',
    organizations.results?.[0].id || ''
  );

  return await getAssetUsage(apiUrl);
}
