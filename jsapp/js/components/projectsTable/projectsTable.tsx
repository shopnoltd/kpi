import React from 'react';
import ReactDOM from 'react-dom';
import PopoverMenu from 'js/popoverMenu';
import LoadingSpinner from 'js/components/common/loadingSpinner';
import bem, {makeBem} from 'js/bem';
import {
  hasVerticalScrollbar,
  getScrollbarWidth,
} from 'js/utils';
import ProjectsTableRow from './projectsTableRow';
import {
  PROJECTS_TABLE_CONTEXTS,
  ORDER_DIRECTIONS,
  PROJECTS_TABLE_COLUMNS,
} from './projectsTableConstants';
import type {
  OrderDirection,
  ProjectsTableContextName,
  ProjectsTableColumn,
} from './projectsTableConstants';
import type {
  AssetResponse,
  MetadataResponse,
} from 'js/dataInterface';
import './projectsTable.scss';

bem.ProjectsTable = makeBem(null, 'projects-table');
bem.ProjectsTable__header = makeBem(bem.ProjectsTable, 'header');
bem.ProjectsTable__body = makeBem(bem.ProjectsTable, 'body');
bem.ProjectsTable__footer = makeBem(bem.ProjectsTable, 'footer');
bem.ProjectsTableRow = makeBem(null, 'projects-table-row');
bem.ProjectsTableRow__link = makeBem(bem.ProjectsTableRow, 'link', 'a');
bem.ProjectsTableRow__buttons = makeBem(bem.ProjectsTableRow, 'buttons');
bem.ProjectsTableRow__column = makeBem(bem.ProjectsTableRow, 'column');
bem.ProjectsTableRow__headerLabel = makeBem(bem.ProjectsTableRow, 'header-label', 'span');
bem.ProjectsTableRow__tags = makeBem(bem.ProjectsTableRow, 'tags', 'div');
bem.ProjectsTableRow__tag = makeBem(bem.ProjectsTableRow, 'tag', 'span');
bem.ProjectsTablePagination = makeBem(null, 'projects-table-pagination');
bem.ProjectsTablePagination__button = makeBem(bem.ProjectsTablePagination, 'button', 'button');
bem.ProjectsTablePagination__index = makeBem(bem.ProjectsTablePagination, 'index');

type OrderChangeCallback = (columnId: string, columnValue: OrderDirection) => void;
type FilterChangeCallback = (columnId: string | null, columnValue: string | null) => void;
type SwitchPageCallback = (pageNumber: number) => void;

interface ProjectsTableProps {
 context: ProjectsTableContextName;
 /** Displays a spinner */
 isLoading?: boolean;
 /** To display contextual empty message when zero assets. */
 emptyMessage?: string;
 /** List of assets to be displayed. */
 assets: AssetResponse[];
 /** Number of assets on all pages. */
 totalAssets: number;
 /** List of available filters values. */
 metadata: MetadataResponse; // this type ??
 /** Seleceted order column id, one of ASSETS_TABLE_COLUMNS. */
 orderColumnId: string;
 /** Seleceted order column value. */
 orderValue: string;
 /** Called when user selects a column for odering. */
 onOrderChange: OrderChangeCallback;
 /** Seleceted filter column, one of ASSETS_TABLE_COLUMNS. */
 filterColumnId: string | null;
 /** Seleceted filter column value. */
 filterValue: string | null;
 /** Called when user selects a column for filtering. */
 onFilterChange: FilterChangeCallback;
 /**
  * For displaying pagination. If you omit any of these, pagination will simply
  * not be rendered. Good to use when you actually don't need it.
  */
 currentPage?: number;
 totalPages?: number;
 /** Called when user clicks page change. */
 onSwitchPage?: SwitchPageCallback;
}

interface ProjectsTableState {
  shouldHidePopover: boolean;
  isPopoverVisible: boolean;
  scrollbarWidth: number | null;
  isFullscreen: boolean;
}

/**
 * Displays a table of assets.
 */
export default class ProjectsTable extends React.Component<
  ProjectsTableProps,
  ProjectsTableState
> {
  constructor(props: ProjectsTableProps){
    super(props);
    this.state = {
      shouldHidePopover: false,
      isPopoverVisible: false,
      scrollbarWidth: null,
      isFullscreen: false,
    };
    this.bodyRef = React.createRef();
  }

  private updateScrollbarWidthBound = this.updateScrollbarWidth.bind(this);

  bodyRef: React.RefObject<any>;

  componentDidMount() {
    this.updateScrollbarWidth();
    window.addEventListener('resize', this.updateScrollbarWidthBound);
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.updateScrollbarWidthBound);
  }

  componentDidUpdate(prevProps: ProjectsTableProps) {
    if (prevProps.isLoading !== this.props.isLoading) {
      this.updateScrollbarWidth();
    }
  }

  toggleFullscreen() {
    this.setState({isFullscreen: !this.state.isFullscreen});
  }

  updateScrollbarWidth() {
    const bodyNode = ReactDOM.findDOMNode(this.bodyRef?.current) as HTMLElement;
    if (bodyNode && hasVerticalScrollbar(bodyNode)) {
      this.setState({scrollbarWidth: getScrollbarWidth()});
    } else {
      this.setState({scrollbarWidth: null});
    }
  }

  switchPage(newPageNumber: number) {
    if (this.props.onSwitchPage) {
      this.props.onSwitchPage(newPageNumber);
    }
  }

  /**
   * This function is only a callback handler, as the asset reordering itself
   * should be handled by the component that is providing the assets list.
   */
  onChangeOrder(columnId: string) {
    if (this.props.orderColumnId === columnId) {
      // clicking already selected column results in switching the order direction
      let newVal = null;
      if (this.props.orderValue === ORDER_DIRECTIONS.ascending) {
        newVal = ORDER_DIRECTIONS.descending;
      } else {
        newVal = ORDER_DIRECTIONS.ascending;
      }
      this.props.onOrderChange(this.props.orderColumnId, newVal);
    } else {
      // change column and revert order direction to default
      this.props.onOrderChange(columnId, PROJECTS_TABLE_COLUMNS[columnId].defaultValue || ORDER_DIRECTIONS.ascending);
    }
  }

  /**
   * This function is only a callback handler, as the asset filtering itself
   * should be handled by the component that is providing the assets list.
   */
  onChangeFilter(columnId: string, filterValue: string | null = null) {
    if (
      this.props.filterColumnId === columnId &&
      this.props.filterValue === filterValue
    ) {
      // when clicking already selected item, clear it
      this.props.onFilterChange(null, null);
    } else {
      this.props.onFilterChange(columnId, filterValue);
    }
  }

  onClearFilter(evt: React.MouseEvent | React.TouchEvent) {
    evt.stopPropagation();
    this.props.onFilterChange(null, null);
  }

  renderHeader(columnDef: ProjectsTableColumn) {
    if (columnDef.orderBy) {
      return this.renderOrderableHeader(columnDef);
    } else if (columnDef.filterBy) {
      return this.renderFilterableHeader(columnDef);
    } else {
      let displayLabel = columnDef.label;
      if (
        columnDef.id === PROJECTS_TABLE_COLUMNS['items-count'].id &&
        this.props.context === PROJECTS_TABLE_CONTEXTS.COLLECTION_CONTENT
      ) {
        displayLabel = t('Questions');
      }
      return (
        <bem.ProjectsTableRow__column m={columnDef.id} disabled>
          {displayLabel}
        </bem.ProjectsTableRow__column>
      );
    }
  }

  onPopoverSetVisible() {
    this.setState({isPopoverVisible: true});
  }

  getColumnMetadata(columnDef: ProjectsTableColumn) {
    switch (columnDef.filterByMetadataName) {
      case 'languages':
        return this.props.metadata.languages;
      case 'countries':
        return this.props.metadata.countries;
      case 'sectors':
        return this.props.metadata.sectors;
      case 'organizations':
        return this.props.metadata.organizations;
      default:
        return [];
    }
  }

  renderFilterableHeader(columnDef: ProjectsTableColumn) {
    const options = this.getColumnMetadata(columnDef);

    if (options.length === 0) {
      return (
        <bem.ProjectsTableRow__column m={columnDef.id} disabled>
          {columnDef.label}
        </bem.ProjectsTableRow__column>
      );
    }

    let icon = (<i className='k-icon k-icon-filter-arrows'/>);
    if (this.props.filterColumnId === columnDef.id) {
      icon = (<i className='k-icon k-icon-close' onClick={this.onClearFilter.bind(this)}/>);
    }

    return (
      <bem.ProjectsTableRow__column m={columnDef.id}>
        <PopoverMenu
          type='projects-table'
          triggerLabel={<span>{columnDef.label} {icon}</span>}
          clearPopover={this.state.shouldHidePopover}
          popoverSetVisible={this.onPopoverSetVisible.bind(this)}
        >
          {options.map((option, index) => {
            let optionValue;
            let optionLabel;

            if (typeof option === 'string') {
              optionValue = option;
              optionLabel = option;
            }
            if (Array.isArray(option)) {
              optionValue = option[0];
              optionLabel = option[1];
            }

            return (
              <bem.PopoverMenu__link
                onClick={this.onChangeFilter.bind(this, columnDef.id, optionValue)}
                key={`option-${index}`}
              >
                {optionLabel}
                {optionValue === this.props.filterValue &&
                  <i className='k-icon k-icon-check'/>
                }
              </bem.PopoverMenu__link>
            );
          })}
        </PopoverMenu>
      </bem.ProjectsTableRow__column>
    );
  }

  renderOrderableHeader(columnDef: ProjectsTableColumn) {
    let hideIcon = false;
    let hideLabel = false;

    // for `icon-status` we don't display empty icon, because the column is
    // too narrow to display label and icon together
    if (columnDef.id === PROJECTS_TABLE_COLUMNS['icon-status'].id) {
      hideIcon = this.props.orderColumnId !== columnDef.id;
      hideLabel = this.props.orderColumnId === columnDef.id;
    }

    // empty icon to take up space in column
    let icon = (<i className='k-icon'/>);
    if (this.props.orderColumnId === columnDef.id) {
      if (this.props.orderValue === ORDER_DIRECTIONS.ascending) {
        icon = (<i className='k-icon k-icon-angle-up'/>);
      }
      if (this.props.orderValue === ORDER_DIRECTIONS.descending) {
        icon = (<i className='k-icon k-icon-angle-down'/>);
      }
    }

    return (
      <bem.ProjectsTableRow__column
        m={columnDef.id}
        onClick={this.onChangeOrder.bind(this, columnDef.id)}
      >
        {!hideLabel &&
          <bem.ProjectsTableRow__headerLabel>{columnDef.label}</bem.ProjectsTableRow__headerLabel>
        }
        {!hideIcon && icon}
      </bem.ProjectsTableRow__column>
    );
  }

  /**
   * Safe: returns nothing if pagination properties are not set.
   */
  renderPagination() {
    if (
      this.props.currentPage &&
      this.props.totalPages &&
      this.props.onSwitchPage
    ) {
      const naturalCurrentPage = this.props.currentPage + 1;
      return (
        <bem.ProjectsTablePagination>
          <bem.ProjectsTablePagination__button
            disabled={this.props.currentPage === 0}
            onClick={this.switchPage.bind(this, this.props.currentPage - 1)}
          >
            <i className='k-icon k-icon-angle-left'/>
            {t('Previous')}
          </bem.ProjectsTablePagination__button>

          <bem.ProjectsTablePagination__index>
            {/* we avoid displaying 1/0 as it doesn't make sense to humans */}
            {naturalCurrentPage}/{this.props.totalPages || 1}
          </bem.ProjectsTablePagination__index>

          <bem.ProjectsTablePagination__button
            disabled={naturalCurrentPage >= this.props.totalPages}
            onClick={this.switchPage.bind(this, this.props.currentPage + 1)}
          >
            {t('Next')}
            <i className='k-icon k-icon-angle-right'/>
          </bem.ProjectsTablePagination__button>
        </bem.ProjectsTablePagination>
      );
    } else {
      return null;
    }
  }

  renderFooter() {
    return (
      <bem.ProjectsTable__footer>
        {this.props.totalAssets !== null &&
          <span>
            {t('##count## items').replace('##count##', String(this.props.totalAssets))}
          </span>
        }

        {this.renderPagination()}

        {this.props.totalAssets !== null &&
          <button
            className='mdl-button'
            onClick={this.toggleFullscreen.bind(this)}
          >
            {t('Toggle fullscreen')}
            <i className='k-icon k-icon-expand' />
          </button>
        }
      </bem.ProjectsTable__footer>
    );
  }

  render() {
    const modifiers: string[] = [this.props.context];
    if (this.state.isFullscreen) {
      modifiers.push('fullscreen');
    }

    return (
      <bem.ProjectsTable m={modifiers}>
        <bem.ProjectsTable__header>
          <bem.ProjectsTableRow m='header'>
            {this.renderHeader(PROJECTS_TABLE_COLUMNS['icon-status'])}
            {this.renderHeader(PROJECTS_TABLE_COLUMNS.name)}
            {this.renderHeader(PROJECTS_TABLE_COLUMNS['items-count'])}
            {this.renderHeader(PROJECTS_TABLE_COLUMNS.owner)}
            {this.props.context === PROJECTS_TABLE_CONTEXTS.PUBLIC_COLLECTIONS &&
              this.renderHeader(PROJECTS_TABLE_COLUMNS['subscribers-count'])
            }
            {this.renderHeader(PROJECTS_TABLE_COLUMNS.languages)}
            {this.props.context === PROJECTS_TABLE_CONTEXTS.PUBLIC_COLLECTIONS &&
              this.renderHeader(PROJECTS_TABLE_COLUMNS['primary-sector'])
            }
            {this.renderHeader(PROJECTS_TABLE_COLUMNS['date-modified'])}

            {this.state.scrollbarWidth !== 0 && this.state.scrollbarWidth !== null &&
              <div
                className='projects-table__scrollbar-padding'
                style={{width: `${this.state.scrollbarWidth}px`}}
              />
            }
          </bem.ProjectsTableRow>
        </bem.ProjectsTable__header>

        <bem.ProjectsTable__body ref={this.bodyRef}>
          {this.props.isLoading &&
            <LoadingSpinner/>
          }

          {!this.props.isLoading && this.props.assets.length === 0 &&
            <bem.ProjectsTableRow m='empty-message'>
              {this.props.emptyMessage || t('There are no assets to display.')}
            </bem.ProjectsTableRow>
          }

          {!this.props.isLoading && this.props.assets.map((asset) =>
            <ProjectsTableRow
              asset={asset}
              key={asset.uid}
              context={this.props.context}
            />
          )}
        </bem.ProjectsTable__body>

        {this.renderFooter()}
      </bem.ProjectsTable>
    );
  }
}
