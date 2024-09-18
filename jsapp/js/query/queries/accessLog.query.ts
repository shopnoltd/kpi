import {keepPreviousData, useQuery} from '@tanstack/react-query';
import {endpoints} from 'js/api.endpoints';
import type {PaginatedResponse} from 'js/dataInterface';
import {fetchGet} from 'js/api';

export interface AccessLog {
  app_label: 'kobo_auth' | string;
  model_name: 'User' | string;
  object_id: number;
  /** User URL */
  user: string;
  user_uid: string;
  username: string;
  action: 'auth' | string;
  metadata: {
    /** E.g. "Firefox (Ubuntu)" */
    source: string;
    auth_type: 'Digest' | string;
    ip_address: string;
  };
  /** Date string */
  date_created: string;
  log_type: 'access' | string;
}

async function getAccessLog(limit: number, offset: number) {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  });
  return fetchGet<PaginatedResponse<AccessLog>>(
    endpoints.ACCESS_LOG_URL + '?' + params,
    {
      errorMessageDisplay: t('There was an error getting the list.'),
    }
  );
}

export default function useAccessLogQuery(
  itemLimit: number,
  pageOffset: number
) {
  return useQuery({
    queryKey: ['accessLog', itemLimit, pageOffset],
    queryFn: () => getAccessLog(itemLimit, pageOffset),
    placeholderData: keepPreviousData,
    // We might want to improve this in future, for now let's not retry
    retry: false,
    // The `refetchOnWindowFocus` option is `true` by default, I'm setting it
    // here so we don't forget about it.
    refetchOnWindowFocus: true,
  });
}
