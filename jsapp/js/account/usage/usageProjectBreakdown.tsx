import React, {useState, useEffect} from 'react';
import styles from './usageProjectBreakdown.module.scss';
import {Link} from 'react-router-dom';
import {ROUTES} from 'jsapp/js/router/routerConstants';
import AssetStatusBadge from 'jsapp/js/components/common/assetStatusBadge';
import LoadingSpinner from 'jsapp/js/components/common/loadingSpinner';
import prettyBytes from 'pretty-bytes';
import type {AssetUsage} from 'js/account/usage/usage.api';
import {getAssetUsageForOrganization} from 'js/account/usage/usage.api';

type ButtonType = 'back' | 'forward';

const ProjectBreakdown = () => {
  const [currentPage, setCurrentPage] = useState(1);
  const [isComponentMounted, setIsComponentMounted] = useState(true);

  const [projectData, setProjectData] = useState<AssetUsage>({
    count: '0',
    next: null,
    previous: null,
    results: [],
  });

   useEffect(() => {
    async function fetchData() {
      try {
        const data = await getAssetUsageForOrganization();
        console.error(data);
        const updatedResults = data.results.map((projectResult) => {
          const assetParts = projectResult.asset.split('/');
          const uid = assetParts[assetParts.length - 2];
          return {
            ...projectResult,
            uid: uid,
          };
        });

        if (isComponentMounted) {
          setProjectData({
            ...data,
            results: updatedResults,
          });
        }
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    }

    fetchData();

    return () => {
      setIsComponentMounted(false);
    };
  }, [isComponentMounted]);

  if (projectData.results.length === 0) {
    return <LoadingSpinner/>;
  }

const calculateRange = (): string => {
  const totalProjects = parseInt(projectData.count);
  const startRange = (currentPage - 1) * 8 + 1;
  const endRange = Math.min(currentPage * 8, totalProjects);
  return `${startRange}-${endRange} of ${totalProjects}`;
};

const removePrefix = (url: string): string => url.replace('http://kf.kobo.local', '');

const handleClick = async (
  event: React.MouseEvent<HTMLButtonElement>,
  buttonType: ButtonType
): Promise<void> => {
  event.preventDefault();

  try {
    if (buttonType === 'back' && projectData.previous) {
      const newData = await getAssetUsageForOrganization(removePrefix(projectData.previous));
      setCurrentPage((prevPage) => Math.max(prevPage - 1, 1));
      setProjectData(newData);
    } else if (buttonType === 'forward' && projectData.next) {
      const newData = await getAssetUsageForOrganization(removePrefix(projectData.next));
      setCurrentPage((prevPage) => Math.min(prevPage + 1, Math.ceil(parseInt(projectData.count) / 8)));
      setProjectData(newData);
    }
  } catch (error) {
    console.error('Error fetching data:', error);
  }
};

  const isActiveBack = currentPage > 1;
  const isActiveForward = currentPage < Math.ceil(parseInt(projectData.count) / 8);

  return (
    <div className={styles.root}>
      <table>
        <thead>
          <tr>
            <th className={styles.projects}>{t('##count## Projects').replace('##count##', projectData.count)}</th>
            <th className={styles.wrap}>{t('Submissions (Total)')}</th>
            <th className={styles.wrap}>{t('Submissions (This billing period)')}</th>
            <th>{t('Data Storage')}</th>
            <th>{t('Transcript Minutes')}</th>
            <th>{t('Translation characters')}</th>
            <th>{t('Status')}</th>
          </tr>
        </thead>

        <tbody>
             {projectData.results.map((project) => (
           <tr key={project.asset}>
              <td>
                <Link className={styles.link} to={ROUTES.FORM_SUMMARY.replace(':uid', project.uid)}>
                  {project.asset__name}
                </Link>
              </td>
              <td>{project.submission_count_all_time.toLocaleString()}</td>
              <td className={styles.currentMonth}>{project.submission_count_current_month.toLocaleString()}</td>
              <td>{prettyBytes(project.storage_bytes)}</td>
              <td>{project.nlp_usage_current_month.total_nlp_asr_seconds.toLocaleString()}</td>
              <td>{project.nlp_usage_current_month.total_nlp_mt_characters.toLocaleString()}</td>
              <td className={styles.badge}>{<AssetStatusBadge deploymentStatus={project.deployment_status}/>}</td>
            </tr>
          ))}
        </tbody>
        <tfoot>
            <div className={styles.pagination}>
            <button className={`${isActiveBack ? styles.active : ''}`} onClick={(e) => handleClick(e, 'back')}>
             <i className='k-icon k-icon-arrow-left' />
            </button>
            <span className={styles.range}>{calculateRange()}</span>
            <button className={`${isActiveForward ? styles.active : ''}`} onClick={(e) => handleClick(e, 'forward')}>
              <i className='k-icon k-icon-arrow-right' />
            </button>
          </div>
        </tfoot>
      </table>
    </div>
  );
};

export default ProjectBreakdown;
