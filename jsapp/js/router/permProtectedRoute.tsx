import React, {Suspense} from 'react';
import {actions} from 'js/actions';
import LoadingSpinner from 'js/components/common/loadingSpinner';
import AccessDenied from 'js/router/accessDenied';
import {withRouter} from './legacy';
import {userCan, userCanPartially} from 'js/components/permissions/utils';
import assetStore from 'js/assetStore';
import type {PermissionCodename} from 'js/components/permissions/permConstants';
import type {WithRouterProps} from 'jsapp/js/router/legacy';
import type {AssetResponse, FailResponse} from 'js/dataInterface';

interface PermProtectedRouteProps extends WithRouterProps {
  /** One of PATHS */
  path: string;
  /** The target route commponent that should be displayed for authenticateed user. */
  protectedComponent: React.ElementType;
  /** The list of permissions needed to be able to see the route. */
  requiredPermissions: PermissionCodename[];
  /** Whether all permissions of `requiredPermissions` are required or only one of them */
  requireAll: boolean;
}

interface PermProtectedRouteState {
  /** Whether loadAsset call was made and ended, regardless of success or failure. */
  isLoadAssetFinished: boolean;
  userHasRequiredPermissions: boolean | null;
  errorMessage?: string;
  asset: AssetResponse | null;
}

/**
 * A gateway component for rendering the route only for a user who has
 * permission to view it. Should be used only for asset routes.
 */
class PermProtectedRoute extends React.Component<
  PermProtectedRouteProps,
  PermProtectedRouteState
> {
  private unlisteners: Function[] = [];

  constructor(props: PermProtectedRouteProps) {
    super(props);
    this.state = this.getInitialState();
    this.unlisteners = [];
  }

  getInitialState(): PermProtectedRouteState {
    return {
      isLoadAssetFinished: false,
      userHasRequiredPermissions: null,
      errorMessage: undefined,
      asset: null,
    };
  }

  componentDidMount() {
    if (!this.props.params.uid) {
      return;
    }

    const assetFromStore = assetStore.getAsset(this.props.params.uid);
    if (assetFromStore) {
      // If this asset was already loaded before, we are not going to be picky
      // and require a fresh one. We only need to know the permissions, and
      // those are most probably up to date.
      // This helps us avoid unnecessary API calls and spinners being displayed
      // in the UI (from this component; see `render()` below).
      this.onLoadAssetCompleted(assetFromStore);
    } else {
      this.unlisteners.push(
        actions.resources.loadAsset.completed.listen(this.onLoadAssetCompleted.bind(this)),
        actions.resources.loadAsset.failed.listen(this.onLoadAssetFailed.bind(this))
      );
      actions.resources.loadAsset({id: this.props.params.uid}, true);
    }
  }

  componentWillUnmount() {
    this.unlisteners.forEach((clb) => {
      clb();
    });
  }

  componentWillReceiveProps(nextProps: PermProtectedRouteProps) {
    if (this.props.params.uid !== nextProps.params.uid) {
      this.setState(this.getInitialState());
      actions.resources.loadAsset({id: nextProps.params.uid});
    } else if (
      this.props.requiredPermissions !== nextProps.requiredPermissions ||
      this.props.requireAll !== nextProps.requireAll ||
      this.props.protectedComponent !== nextProps.protectedComponent
    ) {
      if (this.state.asset) {
        this.setState({
          userHasRequiredPermissions: this.getUserHasRequiredPermissions(
            this.state.asset,
            nextProps.requiredPermissions,
            nextProps.requireAll
          ),
        });
      }
    }
  }

  onLoadAssetCompleted(asset: AssetResponse) {
    if (asset.uid !== this.props.params.uid) {
      return;
    }

    this.setState({
      asset: asset,
      isLoadAssetFinished: true,
      userHasRequiredPermissions: this.getUserHasRequiredPermissions(
        asset,
        this.props.requiredPermissions,
        this.props.requireAll
      ),
    });
  }

  onLoadAssetFailed(response: FailResponse) {
    if (response.status >= 400) {
      this.setState({
        isLoadAssetFinished: true,
        userHasRequiredPermissions: false,
        errorMessage: `${response.status.toString()}: ${
          response.responseJSON?.detail || response.statusText
        }`,
      });
    }
  }

  getUserHasRequiredPermission(
    asset: AssetResponse,
    requiredPermission: PermissionCodename
  ) {
    return (
      // we are ok with either full or partial permission
      userCan(requiredPermission, asset) ||
      userCanPartially(requiredPermission, asset)
    );
  }

  getUserHasRequiredPermissions(
    asset: AssetResponse,
    requiredPermissions: PermissionCodename[],
    all = false
  ) {
    if (all) {
      return requiredPermissions.every((perm) =>
        this.getUserHasRequiredPermission(asset, perm)
      );
    } else {
      return requiredPermissions.some((perm) =>
        this.getUserHasRequiredPermission(asset, perm)
      );
    }
  }

  render() {
    if (!this.state.isLoadAssetFinished) {
      return <LoadingSpinner />;
    } else if (this.state.userHasRequiredPermissions) {
      return (
        <Suspense fallback={<LoadingSpinner />}>
          <this.props.protectedComponent
            {...this.props}
            initialAssetLoadNotNeeded
          />
        </Suspense>
      );
    } else {
      return <AccessDenied errorMessage={this.state.errorMessage} />;
    }
  }
}

export default withRouter(PermProtectedRoute);
