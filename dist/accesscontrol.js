(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.AccessControl = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = _dereq_("./core");
var enums_1 = _dereq_("./enums");
var utils_1 = _dereq_("./utils");
/**
 *  @classdesc
 *  AccessControl class that implements RBAC (Role-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *
 *  Construct an `AccessControl` instance by either passing a grants object (or
 *  array fetched from database) or simple omit `grants` parameter if you are
 *  willing to build it programmatically.
 *
 *  <p><pre><code> var grants = {
 *      role1: {
 *          resource1: {
 *              "create:any": [ attrs ],
 *              "read:own": [ attrs ]
 *          },
 *          resource2: {
 *              "create:any": [ attrs ],
 *              "update:own": [ attrs ]
 *          }
 *      },
 *      role2: { ... }
 *  };
 *  var ac = new AccessControl(grants);</code></pre></p>
 *
 *  The `grants` object can also be an array, such as a flat list
 *  fetched from a database.
 *
 *  <p><pre><code> var flatList = [
 *      { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] },
 *      { role: "role1", resource: "resource1", action: "read:own", attributes: [ attrs ] },
 *      { role: "role2", ... },
 *      ...
 *  ];</code></pre></p>
 *
 *  We turn this list into a hashtable for better performance. We aggregate
 *  the list by roles first, resources second. If possession (in action
 *  value or as a separate property) is omitted, it will default to `"any"`.
 *  e.g. `"create"` —> `"create:any"`
 *
 *  Below are equivalent:
 *  <p><pre><code> var grants = { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] }
 *  var same = { role: "role1", resource: "resource1", action: "create", possession: "any", attributes: [ attrs ] }</code></pre></p>
 *
 *  So we can also initialize with this flat list of grants:
 *  <p><pre><code> var ac = new AccessControl(flatList);
 *  console.log(ac.getGrants());</code></pre></p>
 *
 *  @author   Onur Yıldırım (onur@cutepilot.com)
 *  @license  MIT
 *
 *  @class
 *  @global
 *
 *  @example
 *  var ac = new AccessControl(grants);
 *
 *  ac.grant('admin').createAny('profile');
 *
 *  // or you can chain methods
 *  ac.grant('admin')
 *      .createAny('profile')
 *      .readAny('profile', ["*", "!password"])
 *      .readAny('video')
 *      .deleteAny('video');
 *
 *  // since these permissions have common resources, there is an alternative way:
 *  ac.grant('admin')
 *      .resource('profile').createAny().readAny(null, ["*", "!password"])
 *      .resource('video').readAny()..deleteAny();
 *
 *  ac.grant('user')
 *      .readOwn('profile', ["uid", "email", "address.*", "account.*", "!account.roles"])
 *      .updateOwn('profile', ["uid", "email", "password", "address.*", "!account.roles"])
 *      .deleteOwn('profile')
 *      .createOwn('video', ["*", "!geo.*"])
 *      .readAny('video')
 *      .updateOwn('video', ["*", "!geo.*"])
 *      .deleteOwn('video');
 *
 *  // now we can check for granted or denied permissions
 *  var permission = ac.can('admin').readAny('profile');
 *  permission.granted // true
 *  permission.attributes // ["*", "!password"]
 *  permission.filter(data) // { uid, email, address, account }
 *  // deny permission
 *  ac.deny('admin').createAny('profile');
 *  ac.can('admin').createAny('profile').granted; // false
 *
 *  // To add a grant but deny access via attributes
 *  ac.grant('admin').createAny('profile', []); // no attributes allowed
 *  ac.can('admin').createAny('profile').granted; // false
 */
var AccessControl = (function () {
    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *  @ignore
     *
     *  @param {Object|Array} grants - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     */
    function AccessControl(grants) {
        if (grants === void 0) { grants = {}; }
        this._grants = grants;
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     *
     *  @example
     *  ac.grant('admin')
     *      .createAny(['profile', 'video'])
     *      .deleteAny(['profile', 'video'])
     *      .readAny(['video'])
     *      .readAny('profile', ['*', '!password'])
     *      .grant('user')
     *      .readAny(['profile', 'video'], ['*', '!id', '!password'])
     *      .createOwn(['profile', 'video'])
     *      .deleteOwn(['video']);
     *  // logging underlying grants model
     *  console.log(ac.getGrants());
     *  // outputs:
     *  {
     *    "admin": {
     *      "profile": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*", "!password"]
     *      },
     *      "video": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*"]
     *      }
     *    },
     *    "user": {
     *      "profile": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"]
     *      },
     *      "video": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"],
     *        "delete:own": ["*"]
     *      }
     *    }
     *  }
     */
    AccessControl.prototype.getGrants = function () {
        return this._grants;
    };
    /**
     *  Sets all access grants at once, from an object or array.
     *  Note that this will reset the object and remove all previous grants.
     *  @chainable
     *
     *  @param {Object|Array} grantsObject - A list containing the access grant
     *         definitions.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.setGrants = function (grantsObject) {
        var _this = this;
        this._grants = {};
        var type = utils_1.default.type(grantsObject);
        if (type === 'object') {
            this._grants = grantsObject;
        }
        else if (type === 'array') {
            grantsObject.forEach(function (item) { return utils_1.default.commitToGrants(_this._grants, item, true); });
        }
        return this;
    };
    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.reset = function () {
        this._grants = {};
        return this;
    };
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *  @chainable
     *
     *  @param {String|Array<String>} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a role does not exist, it will be automatically
     *         created.
     *
     *  @param {String|Array<String>} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a extender role does not exist, it will throw.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    AccessControl.prototype.extendRole = function (roles, extenderRoles) {
        utils_1.default.extendRole(this._grants, roles, extenderRoles);
        return this;
    };
    /**
     *  Removes all the given role(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {String|Array<String>} roles - An array of roles to be removed.
     *      Also accepts a string that can be used to remove a single role.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.removeRoles = function (roles) {
        var _this = this;
        var rolesToRemove = utils_1.default.toStringArray(roles);
        rolesToRemove.forEach(function (role) {
            delete _this._grants[role];
        });
        // also remove these roles from $extend list of each remaining role.
        this._each(function (role, roleItem) {
            if (Array.isArray(roleItem.$extend)) {
                roleItem.$extend = utils_1.default.subtractArray(roleItem.$extend, rolesToRemove);
            }
        });
        return this;
    };
    /**
     *  Removes all the given resources for all roles, at once.
     *  Pass the `roles` argument to remove access to resources for those
     *  roles only.
     *  @chainable
     *
     *  @param {String|Array<String>} resources - A single or array of resources to
     *      be removed.
     *  @param {String|Array<String>} [roles] - A single or array of roles to
     *      be removed. If omitted, permissions for all roles to all given
     *      resources will be removed.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.removeResources = function (resources, roles) {
        // _removePermission has a third argument `actionPossession`. if
        // omitted (like below), removes the parent resource object.
        this._removePermission(resources, roles);
        return this;
    };
    /**
     *  Gets all the unique roles that have at least one access information.
     *
     *  @returns {Array<String>}
     *
     *  @example
     *  ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
     *  console.log(ac.getRoles()); // ["admin", "user"]
     */
    AccessControl.prototype.getRoles = function () {
        return Object.keys(this._grants);
    };
    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {Array<String>}
     */
    AccessControl.prototype.getResources = function () {
        // using an object for unique list
        var resources = {};
        this._eachRoleResource(function (role, resource, permissions) {
            resources[resource] = null;
        });
        return Object.keys(resources);
    };
    /**
     *  Checks whether any permissions are granted to the given role.
     *
     *  @param {String} role - Role to be checked.
     *
     *  @returns {Boolean}
     */
    AccessControl.prototype.hasRole = function (role) {
        return this._grants.hasOwnProperty(role);
    };
    /**
     *  Checks whether any permissions are granted for the given resource.
     *
     *  @param {String} resource - Resource to be checked.
     *
     *  @returns {Boolean}
     */
    AccessControl.prototype.hasResource = function (resource) {
        if (typeof resource !== 'string' || resource === '') {
            return false;
        }
        var resources = this.getResources();
        return resources.indexOf(resource) >= 0;
    };
    /**
     *  Gets an instance of `Query` object. This is used to check whether
     *  the defined access is allowed for the given role(s) and resource.
     *  This object provides chainable methods to define and query the access
     *  permissions to be checked.
     *  @name AccessControl#can
     *  @alias AccessControl#access
     *  @function
     *  @chainable
     *
     *  @param {String|Array|IQueryInfo} role - A single role (as a string),
     *      a list of roles (as an array) or an {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}
     *      that fully or partially defines the access to be checked.
     *
     *  @returns {Query} - The returned object provides chainable
     *      methods to define and query the access permissions to be checked.
     *      See {@link ?api=ac#AccessControl~Query|`Query` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
     *
     *  ac.can('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').resource('profile').createAny();
     *
     *  // To check for multiple roles:
     *  ac.can(['admin', 'user']).createOwn('profile');
     *  // Note: when multiple roles checked, acquired attributes are unioned (merged).
     */
    AccessControl.prototype.can = function (role) {
        return new core_1.Query(this._grants, role);
    };
    /**
     *  Alias of `can()`.
     *  @private
     */
    AccessControl.prototype.access = function (role) {
        return this.can(role);
    };
    /**
     *  Gets an instance of `Permission` object that checks and defines
     *  the granted access permissions for the target resource and role.
     *  Normally you would use `AccessControl#can()` method to check for
     *  permissions but this is useful if you need to check at once by passing
     *  a `IQueryInfo` object; instead of chaining methods
     *  (as in `.can(<role>).<action>(<resource>)`).
     *
     *  @param {IQueryInfo} queryInfo
     *         A fulfilled {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}.
     *
     *  @returns {Permission} - An object that provides properties
     *  and methods that defines the granted access permissions. See
     *  {@link ?api=ac#AccessControl~Permission|`Permission` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
     *  var permission = ac.permission({
     *      role: "user",
     *      action: "update:own",
     *      resource: "profile"
     *  });
     *  permission.granted; // Boolean
     *  permission.attributes; // Array e.g. [ 'username', 'password', 'company.*']
     *  permission.filter(object); // { username, password, company: { name, address, ... } }
     */
    AccessControl.prototype.permission = function (queryInfo) {
        return new core_1.Permission(this._grants, queryInfo);
    };
    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given role(s).
     *  @name AccessControl#grant
     *  @alias AccessControl#allow
     *  @function
     *  @chainable
     *
     *  @param {String|Array<String>|IAccessInfo} role
     *         A single role (as a string), a list of roles (as an array) or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}
     *         that fully or partially defines the access to be granted.
     *
     *  @return {Access}
     *          The returned object provides chainable properties to build and
     *          define the access to be granted. See the examples for details.
     *          See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(),
     *      attributes = ['*'];
     *
     *  ac.grant('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').resource('profile').createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *  }).createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create:any',
     *      attributes: attributes
     *  });
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any', // omitting this will default to 'any'
     *      attributes: attributes
     *  });
     *
     *  // To grant same resource and attributes for multiple roles:
     *  ac.grant(['admin', 'user']).createOwn('profile', attributes);
     *
     *  // Note: when attributes is omitted, it will default to `['*']`
     *  // which means all attributes (of the resource) are allowed.
     */
    AccessControl.prototype.grant = function (role) {
        return new core_1.Access(this._grants, role, false);
    };
    /**
     *  Alias of `grant()`.
     *  @private
     */
    AccessControl.prototype.allow = function (role) {
        return this.grant(role);
    };
    /**
     *  Gets an instance of `Access` object. This is used to deny access
     *  to specified resource(s) for the given role(s). Denying will only remove
     *  a previously created grant. So if not granted before, you don't need
     *  to deny an access.
     *  @name AccessControl#deny
     *  @alias AccessControl#reject
     *  @function
     *  @chainable
     *
     *  @param {String|Array<String>|IAccessInfo} role
     *         A single role (as a string), a list of roles (as an array) or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}
     *         that fully or partially defines the access to be denied.
     *
     *  @return {Access}
     *          The returned object provides chainable properties to build and
     *          define the access to be granted.
     *          See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @example
     *  var ac = new AccessControl();
     *
     *  ac.deny('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().role('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().role('admin').resource('profile').createAny();
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *  }).createAny();
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create:any'
     *  });
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any' // omitting this will default to 'any'
     *  });
     *
     *  // To deny same resource for multiple roles:
     *  ac.deny(['admin', 'user']).createOwn('profile');
     */
    AccessControl.prototype.deny = function (role) {
        return new core_1.Access(this._grants, role, true);
    };
    /**
     *  Alias of `deny()`.
     *  @private
     */
    AccessControl.prototype.reject = function (role) {
        return this.deny(role);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     */
    AccessControl.prototype._each = function (callback) {
        var _this = this;
        utils_1.default.eachKey(this._grants, function (role) { return callback(role, _this._grants[role]); });
    };
    /**
     *  @private
     */
    AccessControl.prototype._eachRole = function (callback) {
        utils_1.default.eachKey(this._grants, function (role) { return callback(role); });
    };
    /**
     *  @private
     */
    AccessControl.prototype._eachRoleResource = function (callback) {
        var _this = this;
        var resources, resourceDefinition;
        this._eachRole(function (role) {
            resources = _this._grants[role];
            utils_1.default.eachKey(resources, function (resource) {
                resourceDefinition = role[resource];
                callback(role, resource, resourceDefinition);
            });
        });
    };
    /**
     *  @private
     */
    AccessControl.prototype._removePermission = function (resources, roles, actionPossession) {
        var _this = this;
        resources = utils_1.default.toStringArray(resources);
        if (roles)
            roles = utils_1.default.toStringArray(roles);
        this._eachRoleResource(function (role, resource, permissions) {
            if (resources.indexOf(resource) >= 0
                && (!roles || roles.indexOf(role) >= 0)) {
                if (actionPossession) {
                    delete _this._grants[role][resource][actionPossession];
                }
                else {
                    // this is used for AccessControl#removeResources().
                    delete _this._grants[role][resource];
                }
            }
        });
    };
    Object.defineProperty(AccessControl, "Action", {
        // -------------------------------
        //  PUBLIC STATIC PROPERTIES
        // -------------------------------
        /**
         *  Documented separately in enums/Action
         *  @private
         */
        get: function () {
            return enums_1.Action;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AccessControl, "Possession", {
        /**
         *  Documented separately in enums/Possession
         *  @private
         */
        get: function () {
            return enums_1.Possession;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AccessControl, "Error", {
        /**
         *  Documented separately in AccessControlError
         *  @private
         */
        get: function () {
            return core_1.AccessControlError;
        },
        enumerable: true,
        configurable: true
    });
    // -------------------------------
    //  PUBLIC STATIC METHODS
    // -------------------------------
    /**
     *  A utility method for deep cloning the given data object(s) while
     *  filtering its properties by the given attribute (glob) notations.
     *  Includes all matched properties and removes the rest.
     *
     *  Note that this should be used to manipulate data / arbitrary objects
     *  with enumerable properties. It will not deal with preserving the
     *  prototype-chain of the given object.
     *
     *  @param {Object|Array} data - A single or array of data objects
     *      to be filtered.
     *  @param {Array|String} attributes - The attribute glob notation(s)
     *      to be processed. You can use wildcard stars (*) and negate
     *      the notation by prepending a bang (!). A negated notation
     *      will be excluded. Order of the globs do not matter, they will
     *      be logically sorted. Loose globs will be processed first and
     *      verbose globs or normal notations will be processed last.
     *      e.g. `[ "car.model", "*", "!car.*" ]`
     *      will be sorted as:
     *      `[ "*", "!car.*", "car.model" ]`.
     *      Passing no parameters or passing an empty string (`""` or `[""]`)
     *      will empty the source object.
     *
     *  @returns {Object|Array} - Returns the filtered data object or array
     *      of data objects.
     *
     *  @example
     *  var assets = { notebook: "Mac", car: { brand: "Ford", model: "Mustang", year: 1970, color: "red" } };
     *
     *  var filtered = AccessControl.filter(assets, [ "*", "!car.*", "car.model" ]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets, "*"); // or AccessControl.filter(assets, ["*"]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets); // or AccessControl.filter(assets, "");
     *  console.log(assets); // {}
     */
    AccessControl.filter = function (data, attributes) {
        utils_1.default.filterAll(data, attributes);
    };
    /**
     *  Checks whether the given object is an instance of `AccessControl.Error`.
     *  @name AccessControl.isACError
     *  @alias AccessControl.isAccessControlError
     *  @function
     *
     *  @param {Any} object
     *         Object to be checked.
     *
     *  @returns {Boolean}
     */
    AccessControl.isACError = function (object) {
        return object instanceof core_1.AccessControlError;
    };
    /**
     *  Alias of `isACError`
     *  @private
     */
    AccessControl.isAccessControlError = function (object) {
        return AccessControl.isACError(object);
    };
    return AccessControl;
}());
exports.default = AccessControl;

},{"./core":6,"./enums":9,"./utils":10}],2:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var enums_1 = _dereq_("../enums");
var utils_1 = _dereq_("../utils");
/**
 *  Represents the inner `Access` class that helps build an access information
 *  to be granted or denied; and finally commits it to the underlying grants
 *  model. You can get a first instance of this class by calling
 *  `AccessControl#grant()` or `AccessControl#deny()` methods.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Access = (function () {
    /**
     *  Initializes a new instance of `Access`.
     *  @private
     *
     *  @param {Any} grants
     *         Main grants object.
     *  @param {String|Array<String>|IAccessInfo} roleOrInfo
     *         Either an `IAccessInfo` object, a single or an array of
     *         roles. If an object is passed, possession and attributes
     *         properties are optional. CAUTION: if attributes is omitted,
     *         and access is not denied, it will default to `["*"]` which means
     *         "all attributes allowed". If possession is omitted, it will
     *         default to `"any"`.
     *  @param {Boolean} denied
     *         Specifies whether this `Access` is denied.
     */
    function Access(grants, roleOrInfo, denied) {
        if (denied === void 0) { denied = false; }
        /**
         *  Inner `IAccessInfo` object.
         *  @protected
         *  @type {IAccessInfo}
         */
        this._ = {};
        this._grants = grants;
        this._.denied = denied;
        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
            this.role(roleOrInfo);
        }
        else if (utils_1.default.type(roleOrInfo) === 'object') {
            // if an IAccessInfo instance is passed and it has 'action' defined, we
            // should directly commit it to grants.
            roleOrInfo.denied = denied;
            this._ = utils_1.default.resetAttributes(roleOrInfo);
            if (utils_1.default.isInfoFulfilled(this._))
                utils_1.default.commitToGrants(this._grants, this._, true);
        }
    }
    Object.defineProperty(Access.prototype, "denied", {
        // -------------------------------
        //  PUBLIC PROPERTIES
        // -------------------------------
        /**
         *  Specifies whether this access is initally denied.
         *  @name AccessControl~Access#denied
         *  @type {Boolean}
         *  @readonly
         */
        get: function () {
            return this._.denied;
        },
        enumerable: true,
        configurable: true
    });
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the role(s) for this `Access` instance.
     *  @param {String|Array<String>} value
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.role = function (value) {
        this._.role = value;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Target resource for this `Access` instance.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.resource = function (value) {
        this._.resource = value;
        return this;
    };
    /**
     *  Sets the array of allowed attributes for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Attributes to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.attributes = function (value) {
        this._.attributes = value;
        return this;
    };
    /**
     *  Sets the roles to be extended for this `Access` instance.
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.extend = function (roles) {
        utils_1.default.extendRole(this._grants, this._.role, roles);
        return this;
    };
    /**
     *  Shorthand to switch to a new `Access` instance with a different role
     *  within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either a single or an array of roles or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('user').createOwn('video')
     *    .grant('admin').updateAny('video');
     */
    Access.prototype.grant = function (roleOrInfo) {
        return (new Access(this._grants, roleOrInfo, false)).attributes(['*']);
    };
    /**
     *  Shorthand to switch to a new `Access` instance with a different
     *  (or same) role within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either a single or an array of roles or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('admin').createAny('video')
     *    .deny('user').deleteAny('video');
     */
    Access.prototype.deny = function (roleOrInfo) {
        return (new Access(this._grants, roleOrInfo, true)).attributes([]);
    };
    /**
     *  Sets the action to `"create"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid
     *  data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.createOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.OWN, resource, attributes);
    };
    /**
     *  Sets the action to `"create"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#create
     *  @name AccessControl~Access#createAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.createAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias if `createAny`
     *  @private
     */
    Access.prototype.create = function (resource, attributes) {
        return this.createAny(resource, attributes);
    };
    /**
     *  Sets the action to `"read"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.readOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.OWN, resource, attributes);
    };
    /**
     *  Sets the action to `"read"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#read
     *  @name AccessControl~Access#readAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.readAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias if `readAny`
     *  @private
     */
    Access.prototype.read = function (resource, attributes) {
        return this.readAny(resource, attributes);
    };
    /**
     *  Sets the action to `"update"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.updateOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource, attributes);
    };
    /**
     *  Sets the action to `"update"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#update
     *  @name AccessControl~Access#updateAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.updateAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias if `updateAny`
     *  @private
     */
    Access.prototype.update = function (resource, attributes) {
        return this.updateAny(resource, attributes);
    };
    /**
     *  Sets the action to `"delete"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.deleteOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.OWN, resource, attributes);
    };
    /**
     *  Sets the action to `"delete"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#delete
     *  @name AccessControl~Access#deleteAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.deleteAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias if `deleteAny`
     *  @private
     */
    Access.prototype.delete = function (resource, attributes) {
        return this.deleteAny(resource, attributes);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action     [description]
     *  @param {String} possession [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype._prepareAndCommit = function (action, possession, resource, attributes) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        if (attributes)
            this._.attributes = attributes;
        if (this._.denied) {
            this._.attributes = [];
        }
        else {
            // if omitted and not denied, all attributes are allowed
            this._.attributes = this._.attributes ? utils_1.default.toStringArray(this._.attributes) : ['*'];
        }
        utils_1.default.commitToGrants(this._grants, this._, false);
        // important: reset attributes for chained methods
        this._.attributes = undefined;
        return this;
    };
    return Access;
}());
exports.default = Access;

},{"../enums":9,"../utils":10}],3:[function(_dereq_,module,exports){
"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
/**
 *  Error class specific to `AccessControl`.
 *  @readonly
 *  @name AccessControl.Error
 *  @class
 *  @static
 */
var AccessControlError = (function (_super) {
    __extends(AccessControlError, _super);
    function AccessControlError(message) {
        if (message === void 0) { message = ''; }
        var _this = _super.call(this, message) || this;
        _this.message = message;
        _this.name = 'AccessControlError';
        // http://stackoverflow.com/a/41429145/112731
        Object.setPrototypeOf(_this, AccessControlError.prototype);
        return _this;
    }
    return AccessControlError;
}(Error));
exports.default = AccessControlError;

},{}],4:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var utils_1 = _dereq_("../utils");
/**
 *  Represents the inner `Permission` class that defines the granted or denied
 *  access permissions for the target resource and role.
 *
 *  You can check for a permission in two ways:
 *
 *  <ul>
 *  <li>
 *  You can first obtain a {@link ?api=ac#AccessControl~Query|`Query` instance}
 *  via {@link ?api=ac#AccessControl#can|`AccessControl#can`} which returns
 *  a `Permission` instance when an action method such as
 *  {@link ?api=ac#AccessControl~Query#createAny|`.createAny()`} is
 *  called.
 *  <p><pre><code> var permission = ac.can('user').createAny('video');
 *  console.log(permission.granted); // boolean</code></pre></p>
 *  </li>
 *  <li>
 *  Or you can call {@link ?api=ac#AccessControl#permission|`AccessControl#permission`}
 *  by passing a fulfilled {@link ?api=ac#AccessControl#IQueryInfo|`IQueryInfo` object}.
 *  <p><pre><code> var permission = ac.permission({
 *      role: 'user',
 *      resource: 'video',
 *      action: 'create',
 *      possession: 'any'
 *  });
 *  console.log(permission.granted); // boolean</code></pre></p>
 *  </li>
 *  </ul>
 *
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Permission = (function () {
    /**
     *  Initializes a new `Permission` instance.
     *  @private
     *
     *  @param {IQueryInfo} query
     *         An `IQueryInfo` arbitrary object.
     */
    function Permission(grants, query) {
        /**
         *  @private
         */
        this._ = {};
        this._.role = query.role;
        this._.resource = query.resource;
        this._.attributes = utils_1.default.getUnionAttrsOfRoles(grants, query);
    }
    Object.defineProperty(Permission.prototype, "roles", {
        /**
         *  Specifies the roles for which the permission is queried for.
         *  Even if the permission is queried for a single role, this will still
         *  return an array.
         *
         *  If the returned array has multiple roles, this does not necessarily mean
         *  that the queried permission is granted or denied for each and all roles.
         *  Note that when a permission is queried for multiple roles, attributes
         *  are unioned (merged) for all given roles. This means "at least one of
         *  these roles" have the permission for this action and resource attribute.
         *
         *  @name AccessControl~Permission#roles
         *  @type {Array<String>}
         *  @readonly
         */
        get: function () {
            return this._.role;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "resource", {
        /**
         *  Specifies the target resource for which the permission is queried for.
         *
         *  @name AccessControl~Permission#resource
         *  @type {String}
         *  @readonly
         */
        get: function () {
            return this._.resource;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "attributes", {
        /**
         *  Gets an array of allowed attributes which are defined via
         *  Glob notation. If access is not granted, this will be an empty array.
         *
         *  Note that when a permission is queried for multiple roles, attributes
         *  are unioned (merged) for all given roles. This means "at least one of
         *  these roles" have the permission for this action and resource attribute.
         *
         *  @name AccessControl~Permission#attributes
         *  @type {Array<String>}
         *  @readonly
         */
        get: function () {
            return this._.attributes;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "granted", {
        /**
         *  Specifies whether the permission is granted. If `true`, this means at
         *  least one attribute of the target resource is allowed.
         *
         *  @name AccessControl~Permission#granted
         *  @type {Boolean}
         *  @readonly
         */
        get: function () {
            if (!this.attributes || this.attributes.length === 0)
                return false;
            // just one non-negated attribute is enough.
            return this.attributes.some(function (attr) {
                return attr.trim().slice(0, 1) !== '!';
            });
        },
        enumerable: true,
        configurable: true
    });
    /**
     *  Filters the given data object (or array of objects) by the permission
     *  attributes and returns this data with allowed attributes.
     *
     *  @param {Object|Array} data
     *         Data object to be filtered. Either a single object or array
     *         of objects.
     *
     *  @returns {Object|Array}
     *           The filtered data object.
     */
    Permission.prototype.filter = function (data) {
        return utils_1.default.filterAll(data, this.attributes);
    };
    return Permission;
}());
exports.default = Permission;

},{"../utils":10}],5:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = _dereq_("../core");
var enums_1 = _dereq_("../enums");
var utils_1 = _dereq_("../utils");
/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<role>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Query = (function () {
    /**
     *  Initializes a new instance of `Query`.
     *  @private
     *
     *  @param {Any} grants
     *         Underlying grants model against which the permissions will be
     *         queried and checked.
     *  @param {string|Array<String>|IQueryInfo} [role]
     *         Either a single or array of roles or an
     *         {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` arbitrary object}.
     */
    function Query(grants, role) {
        /**
         *  Inner `IQueryInfo` object.
         *  @protected
         *  @type {IQueryInfo}
         */
        this._ = {};
        this._grants = grants;
        // if this is a (permission) object, we directly build attributes from
        // grants.
        if (utils_1.default.type(role) === 'object') {
            this._ = role;
        }
        else {
            // if this is just role(s); a string or array; we start building
            // the grant object for this.
            this._.role = role;
        }
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the role(s) for this `Query` instance.
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.role = function (role) {
        this._.role = role;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.resource = function (resource) {
        this._.resource = resource;
        return this;
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "create" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.createOwn = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "create" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.createAny = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `createAny`
     *  @private
     */
    Query.prototype.create = function (resource) {
        return this.createAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "read" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.readOwn = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "read" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.readAny = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `readAny`
     *  @private
     */
    Query.prototype.read = function (resource) {
        return this.readAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "update" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.updateOwn = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "update" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.updateAny = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `updateAny`
     *  @private
     */
    Query.prototype.update = function (resource) {
        return this.updateAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "delete" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.deleteOwn = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can "delete" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.deleteAny = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `deleteAny`
     *  @private
     */
    Query.prototype.delete = function (resource) {
        return this.deleteAny(resource);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action
     *  @param {String} possession
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    Query.prototype._getPermission = function (action, possession, resource) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        return new core_1.Permission(this._grants, this._);
    };
    return Query;
}());
exports.default = Query;

},{"../core":6,"../enums":9,"../utils":10}],6:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var AccessControlError_1 = _dereq_("./AccessControlError");
exports.AccessControlError = AccessControlError_1.default;
var Access_1 = _dereq_("./Access");
exports.Access = Access_1.default;
var Query_1 = _dereq_("./Query");
exports.Query = Query_1.default;
var Permission_1 = _dereq_("./Permission");
exports.Permission = Permission_1.default;

},{"./Access":2,"./AccessControlError":3,"./Permission":4,"./Query":5}],7:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 *  Enumerates the possible actions of a role.
 *  An action defines the type of an operation that will be executed on a
 *  "resource" by a "role".
 *  This is known as CRUD (CREATE, READ, UPDATE, DELETE).
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
var Action = {
    /**
     *  Specifies a CREATE action to be performed on a resource.
     *  For example, an HTTP POST request or an INSERT database operation.
     *  @type {String}
     */
    CREATE: 'create',
    /**
     *  Specifies a READ action to be performed on a resource.
     *  For example, an HTTP GET request or an database SELECT operation.
     *  @type {String}
     */
    READ: 'read',
    /**
     *  Specifies an UPDATE action to be performed on a resource.
     *  For example, an HTTP PUT or POST request or an database UPDATE operation.
     *  @type {String}
     */
    UPDATE: 'update',
    /**
     *  Specifies a DELETE action to be performed on a resource.
     *  For example, an HTTP DELETE request or a database DELETE operation.
     *  @type {String}
     */
    DELETE: 'delete'
};
exports.default = Action;

},{}],8:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 *  Enumerates the possible possessions of a resource, for an action.
 *  A possession defines whether the action is (or not) to be performed on "own"
 *  resource(s) of the current subject or "any" resources - including "own".
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
var Possession = {
    /**
     *  Indicates that the action is (or not) to be performed on <b>own</b>
     *  resource(s) of the current subject.
     *  @type {String}
     */
    OWN: 'own',
    /**
     *  Indicates that the action is (or not) to be performed on <b>any</b>
     *  resource(s); including <i>own</i> resource(s) of the current subject.
     *  @type {String}
     */
    ANY: 'any'
};
exports.default = Possession;

},{}],9:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Action_1 = _dereq_("./Action");
exports.Action = Action_1.default;
var Possession_1 = _dereq_("./Possession");
exports.Possession = Possession_1.default;
var actions = Object.keys(Action_1.default).map(function (k) { return Action_1.default[k]; });
exports.actions = actions;
var possessions = Object.keys(Possession_1.default).map(function (k) { return Possession_1.default[k]; });
exports.possessions = possessions;

},{"./Action":7,"./Possession":8}],10:[function(_dereq_,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = _dereq_("notation");
// own modules
var enums_1 = _dereq_("./enums");
var core_1 = _dereq_("./core");
var utils = {
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value;
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        throw new core_1.AccessControlError('Cannot convert value to array!');
    },
    isFilledStringArray: function (arr) {
        for (var _i = 0, arr_1 = arr; _i < arr_1.length; _i++) {
            var s = arr_1[_i];
            if (typeof s !== 'string' || s.trim() === '')
                return false;
        }
        return true;
    },
    isStringOrArray: function (value) {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },
    isEmptyArray: function (value) {
        return Array.isArray(value) && value.length === 0;
    },
    uniqConcat: function (arrA, arrB) {
        var arr = arrA.concat();
        arrB.forEach(function (b) {
            if (arr.indexOf(b) < 0)
                arr.push(b);
        });
        return arr;
    },
    subtractArray: function (arrA, arrB) {
        return arrA.concat().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    eachKey: function (o, callback) {
        return Object.keys(o).forEach(callback);
    },
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles: function (grants, roles) {
        roles = utils.toStringArray(roles);
        var arr = roles.concat();
        roles.forEach(function (roleName) {
            var role = grants[roleName];
            if (Array.isArray(role.$extend)) {
                arr = utils.uniqConcat(arr, role.$extend);
            }
        });
        return arr;
    },
    normalizeActionPossession: function (info) {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            throw new core_1.AccessControlError("Invalid action: " + info.action);
        }
        var s = info.action.split(':');
        if (enums_1.actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new core_1.AccessControlError("Invalid action: " + s[0]);
        }
        info.action = s[0].trim().toLowerCase();
        // validate and normalize possession
        var poss = info.possession || s[1];
        if (poss) {
            if (enums_1.possessions.indexOf(poss.trim().toLowerCase()) < 0) {
                throw new core_1.AccessControlError("Invalid action possession: " + poss);
            }
            else {
                info.possession = poss.trim().toLowerCase();
            }
        }
        else {
            // if no possession is set, we'll default to "any".
            info.possession = enums_1.Possession.ANY;
        }
        return info;
    },
    normalizeQueryInfo: function (query, all) {
        if (all === void 0) { all = false; }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(query.role));
        }
        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new core_1.AccessControlError("Invalid resource: \"" + query.resource + "\"");
        }
        query.resource = query.resource.trim();
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all)
            query = utils.normalizeActionPossession(query);
        return query;
    },
    normalizeAccessInfo: function (access, all) {
        if (all === void 0) { all = false; }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (!utils.isFilledStringArray(access.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(access.role));
        }
        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (!utils.isFilledStringArray(access.resource)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(access.resource));
        }
        // normalize attributes
        if (access.denied || (Array.isArray(access.attributes) && access.attributes.length === 0)) {
            access.attributes = [];
        }
        else {
            // if omitted and not denied, all attributes are allowed
            access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        }
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all)
            access = utils.normalizeActionPossession(access);
        return access;
    },
    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    resetAttributes: function (access) {
        if (access.denied) {
            access.attributes = [];
            return access;
        }
        if (!access.attributes || utils.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    },
    /**
     *  Checks whether the given access info can be commited to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    isInfoFulfilled: function (info) {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },
    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @param {Boolean} normalizeAll
     *         Specifies whether to validate and normalize all properties of
     *         the inner `IAccessInfo` object, including `action` and `possession`.
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants: function (grants, access, normalizeAll) {
        if (normalizeAll === void 0) { normalizeAll = false; }
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        access.role.forEach(function (role) {
            if (!grants.hasOwnProperty(role))
                grants[role] = {};
            var grantItem = grants[role];
            var ap = access.action + ':' + access.possession;
            access.resource.forEach(function (res) {
                if (!grantItem.hasOwnProperty(res))
                    grantItem[res] = {};
                // If possession (in action value or as a separate property) is
                // omitted, it will default to "any". e.g. "create" —>
                // "create:any"
                grantItem[res][ap] = access.attributes;
            });
        });
        // console.log('======================');
        // console.log('committing >>> ', JSON.stringify(access));
        // console.log('----------------------');
        // console.log('committed >>>\n', JSON.stringify(grants, null, '  '));
        // console.log('======================');
    },
    /**
     *  When more than one role is passed, we union the permitted attributes
     *  for all given roles; so we can check whether "at least one of these
     *  roles" have the permission to execute this action.
     *  e.g. `can(['admin', 'user']).createAny('video')`
     *
     *  @param {Any} grants
     *  @param {IQueryInfo} query
     *
     *  @returns {Array<String>} - Array of union'ed attributes.
     */
    getUnionAttrsOfRoles: function (grants, query) {
        if (!grants) {
            throw new core_1.AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);
        var grantItem;
        var resource;
        var attrsList = [];
        // get roles and extended roles in a flat array
        var roles = utils.getFlatRoles(grants, query.role);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach(function (role, index) {
            grantItem = grants[role];
            if (grantItem) {
                resource = grantItem[query.resource];
                if (resource) {
                    // e.g. resource['create:own']
                    // If action has possession "any", it will also return
                    // `granted=true` for "own", if "own" is not defined.
                    attrsList.push((resource[query.action + ':' + query.possession]
                        || resource[query.action + ':any']
                        || []).concat());
                    // console.log(resource, 'for:', action + '.' + possession);
                }
            }
        });
        // union all arrays of (permitted resource) attributes (for each role)
        // into a single array.
        var attrs = [];
        var len = attrsList.length;
        if (len > 0) {
            attrs = attrsList[0];
            var i = 1;
            while (i < len) {
                attrs = Notation.Glob.union(attrs, attrsList[i]);
                i++;
            }
        }
        return attrs;
    },
    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles: function (grants, roles) {
        var non = [];
        for (var _i = 0, roles_1 = roles; _i < roles_1.length; _i++) {
            var role = roles_1[_i];
            if (!grants.hasOwnProperty(role))
                non.push(role);
        }
        return non;
    },
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *
     *  @param {Any} grants
     *  @param {String|Array<String>} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a role does not exist, it will be automatically
     *         created.
     *
     *  @param {String|Array<String>} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a extender role does not exist, it will throw.
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    extendRole: function (grants, roles, extenderRoles) {
        var arrExtRoles = utils.toStringArray(extenderRoles);
        var nonExistentExtRoles = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new core_1.AccessControlError("Cannot extend with non-existent role(s): \"" + nonExistentExtRoles.join(', ') + "\"");
        }
        utils.toStringArray(roles).forEach(function (role) {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new core_1.AccessControlError("Attempted to extend role \"" + role + "\" by itself.");
            }
            if (!grants.hasOwnProperty(role)) {
                grants[role] = {
                    $extend: arrExtRoles.concat()
                };
            }
            else {
                var r = grants[role];
                if (Array.isArray(r.$extend)) {
                    r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
                }
                else {
                    r.$extend = arrExtRoles.concat();
                }
            }
        });
    },
    filter: function (object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new Notation(object);
        return notation.filter(attributes).value;
    },
    filterAll: function (arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return utils.filter(o, attributes);
        });
    }
};
exports.default = utils;

},{"./core":6,"./enums":9,"notation":11}],11:[function(_dereq_,module,exports){
!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define("notation",[],t):"object"==typeof exports?exports.notation=t():e.notation=t()}(this,function(){return function(e){function t(r){if(n[r])return n[r].exports;var i=n[r]={exports:{},id:r,loaded:!1};return e[r].call(i.exports,i,i.exports,t),i.loaded=!0,i.exports}var n={};return t.m=e,t.c=n,t.p="dist/",t(0)}([function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{"default":e}}var i=n(1),a=r(i);e.exports=a["default"]},function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{"default":e}}function i(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}Object.defineProperty(t,"__esModule",{value:!0});var a=function(){function e(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}return function(t,n,r){return n&&e(t.prototype,n),r&&e(t,r),t}}(),o=n(2),u=r(o),l=n(3),s=r(l),c=n(4),f=r(c),v={SOURCE:"Invalid source object.",DEST:"Invalid destination object.",NOTATION:"Invalid notation: ",NOTA_OBJ:"Invalid notations object: "},h=function(){function e(){var t=arguments.length<=0||void 0===arguments[0]?{}:arguments[0];if(i(this,e),!u["default"].isObject(t))throw new f["default"](v.SOURCE);this._source=t}return a(e,[{key:"each",value:function(t){var n=this,r=this._source,i=Object.keys(r);u["default"].each(i,function(i,a,o){var l=r[i],s=void 0;u["default"].isObject(l)?(s=new e(l),s.each(function(e,n,a,o){var u=i+"."+e;t.call(s,u,n,a,r)})):t.call(n,i,i,l,r)})}},{key:"eachKey",value:function(e){return this.each(e)}},{key:"eachValue",value:function(t,n){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");var r=this._source;e.eachNote(t,function(e,t,i,a){return r=u["default"].hasOwn(r,t)?r[t]:void 0,n(r,e,t,i,a)===!1?!1:void 0})}},{key:"getNotations",value:function(){var e=[];return this.each(function(t,n,r,i){e.push(t)}),e}},{key:"flatten",value:function(){var e={};return this.each(function(t,n,r,i){e[t]=r}),this._source=e,this}},{key:"expand",value:function(){return this._source=e.create({}).merge(this._source).value,this}},{key:"aggregate",value:function(){return this.expand()}},{key:"inspect",value:function(t){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");var n=this._source,r={has:!1,value:void 0};return e.eachNote(t,function(e,t,i,a){return u["default"].hasOwn(n,t)?(n=n[t],void(r={has:!0,value:n})):(r={has:!1,value:void 0},!1)}),r}},{key:"inspectRemove",value:function(t){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");var n=void 0,r=void 0;if(t.indexOf(".")<0)r=t,n=this._source;else{var i=e.parent(t);r=e.last(t),n=this.inspect(i).value}var a=void 0;return u["default"].hasOwn(n,r)?(a={has:!0,value:n[r]},delete n[r]):a={has:!1,value:void 0},a}},{key:"has",value:function(e){return this.inspect(e).has}},{key:"hasDefined",value:function(e){return void 0!==this.inspect(e).value}},{key:"get",value:function(e,t){var n=this.inspect(e);return n.has?n.value:t}},{key:"set",value:function(t,n){var r=arguments.length<=2||void 0===arguments[2]?!0:arguments[2];if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");var i=this._source,a=void 0;return e.eachNote(t,function(e,t,o,l){a=o===l.length-1,u["default"].hasOwn(i,t)?a?r&&(i[t]=n):i=i[t]:i=i[t]=a?n:{}}),this}},{key:"merge",value:function(e){var t=this,n=arguments.length<=1||void 0===arguments[1]?!0:arguments[1];if(!u["default"].isObject(e))throw new f["default"](v.NOTA_OBJ+"`"+e+"`");var r=void 0;return u["default"].each(Object.keys(e),function(i,a,o){r=e[i],t.set(i,r,n)}),this}},{key:"separate",value:function(t){var n=this;if(!u["default"].isArray(t))throw new f["default"](v.NOTA_OBJ+"`"+t+"`");var r=new e({});return u["default"].each(t,function(e,t,i){var a=n.inspectRemove(e);r.set(e,a.value)}),this._source=r._source,this}},{key:"filter",value:function(t){var n=this,r=this.value,i=u["default"].deepCopy(r);if(u["default"].stringOrArrayOf(t,"*"))return this._source=i,this;if(0===arguments.length||u["default"].stringOrArrayOf(t,""))return this._source={},this;var a=u["default"].isArray(t)?s["default"].sort(t.concat()):[t],o=void 0;"*"===a[0]?(o=new e(i),a.shift()):o=new e({});var l=void 0,c=void 0,f=void 0;return u["default"].each(a,function(e,t,i){return l=new s["default"](e),c=".*"===l.normalized.slice(-2),f=c?l.normalized.slice(0,-2):l.normalized,f.indexOf("*")<0?(l.isNegated?(o.remove(f),c&&o.set(f,{},!0)):o.copyFrom(r,f,null,!0),!0):void n.each(function(e,t,n,r){l.test(e)&&(l.isNegated?o.remove(e):o.set(e,n,!0))})}),this._source=o.value,this}},{key:"remove",value:function(e){return this.inspectRemove(e),this}},{key:"clone",value:function(){var t=u["default"].deepCopy(this.value);return new e(t)}},{key:"copyTo",value:function(t,n){var r=arguments.length<=2||void 0===arguments[2]?null:arguments[2],i=arguments.length<=3||void 0===arguments[3]?!0:arguments[3];if(!u["default"].isObject(t))throw new f["default"](v.DEST);var a=this.inspect(n);return a.has&&new e(t).set(r||n,a.value,i),this}},{key:"copyFrom",value:function(t,n){var r=arguments.length<=2||void 0===arguments[2]?null:arguments[2],i=arguments.length<=3||void 0===arguments[3]?!0:arguments[3];if(!u["default"].isObject(t))throw new f["default"](v.DEST);var a=new e(t).inspect(n);return a.has&&this.set(r||n,a.value,i),this}},{key:"moveTo",value:function(t,n){var r=arguments.length<=2||void 0===arguments[2]?null:arguments[2],i=arguments.length<=3||void 0===arguments[3]?!0:arguments[3];if(!u["default"].isObject(t))throw new f["default"](v.DEST);var a=this.inspectRemove(n);return a.has&&new e(t).set(r||n,a.value,i),this}},{key:"moveFrom",value:function(t,n){var r=arguments.length<=2||void 0===arguments[2]?null:arguments[2],i=arguments.length<=3||void 0===arguments[3]?!0:arguments[3];if(!u["default"].isObject(t))throw new f["default"](v.DEST);var a=new e(t).inspectRemove(n);return a.has&&this.set(r||n,a.value,i),this}},{key:"rename",value:function(e,t,n){return t?this.moveTo(this._source,e,t,n):this}},{key:"renote",value:function(e,t,n){return this.rename(e,t,n)}},{key:"extract",value:function(e,t){var n={};return this.copyTo(n,e,t),n}},{key:"copyToNew",value:function(e,t){return this.extract(e,t)}},{key:"extrude",value:function(e,t){var n={};return this.moveTo(n,e,t),n}},{key:"moveToNew",value:function(e,t){return this.extrude(e,t)}},{key:"value",get:function(){return this._source}}],[{key:"create",value:function(){var t=arguments.length<=0||void 0===arguments[0]?{}:arguments[0];return new e(t)}},{key:"isValid",value:function(e){return"string"==typeof e&&/^[^\s\.!]+(\.[^\s\.!]+)*$/.test(e)}},{key:"first",value:function(t){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");return t.split(".")[0]}},{key:"last",value:function(t){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");return t.split(".").reverse()[0]}},{key:"parent",value:function(t){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");return t.indexOf(".")>=0?t.replace(/\.[^\.]*$/,""):null}},{key:"eachNote",value:function(t,n){if(!e.isValid(t))throw new f["default"](v.NOTATION+"`"+t+"`");var r=t.split("."),i=[],a=void 0;u["default"].each(r,function(e,t,o){return i.push(e),a=i.join("."),n(a,e,t,r)===!1?!1:void 0},e)}}]),e}();h.Error=f["default"],h.Glob=s["default"],t["default"]=h},function(e,t){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var n=Object.prototype.toString,r={isObject:function(e){return"[object Object]"===n.call(e)},isArray:function(e){return"[object Array]"===n.call(e)},hasOwn:function(e,t){return e&&"function"==typeof e.hasOwnProperty&&e.hasOwnProperty(t)},deepCopy:function(e){if(!r.isObject(e))return e;var t,n,i={};for(t in e)r.hasOwn(e,t)&&(n=e[t],i[t]=r.isObject(n)?r.deepCopy(n):n);return i},each:function(e,t,n){for(var r=e.length,i=-1;++i<r&&t.call(n,e[i],i,e)!==!1;);},eachRight:function(e,t){for(var n=e.length;n--&&t(e[n],n,e)!==!1;);},pregQuote:function(e,t){return String(e).replace(new RegExp("[.\\\\+*?\\[\\^\\]$(){}=!<>|:\\"+(t||"")+"-]","g"),"\\$&")},stringOrArrayOf:function(e,t){return"string"==typeof e&&e===t||r.isArray(e)&&1===e.length&&e[0]===t}};t["default"]=r},function(e,t,n){"use strict";function r(e){return e&&e.__esModule?e:{"default":e}}function i(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}Object.defineProperty(t,"__esModule",{value:!0});var a=function(){function e(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}return function(t,n,r){return n&&e(t.prototype,n),r&&e(t,r),t}}(),o=n(2),u=r(o),l=n(4),s=r(l),c=function(){function e(t){if(i(this,e),!e.isValid(t))throw new s["default"]('Invalid notation glob: "'+t+'"');this.glob=t;var n=e.normalize(t);this.normalized=n.glob,this.isNegated=n.isNegated,this.regexp=e.toRegExp(this.normalized),this.levels=this.normalized.split(".")}return a(e,[{key:"test",value:function(e){return"*"===this.normalized||""!==this.normalized&&""!==e&&this.regexp.test(e)}}],[{key:"create",value:function(t){return new e(t)}},{key:"toRegExp",value:function(e,t){return e=u["default"].pregQuote(e).replace(/\\\*/g,"[^\\s\\.]*").replace(/\\\?/g,"."),new RegExp("^"+e,t||"")}},{key:"normalize",value:function(t){t=t.replace(/\*+/g,"*"),t=e.isValid(t)?t:"";var n="!"===t.slice(0,1);return t=n?t.slice(1):t,{glob:t,isNegated:n}}},{key:"isValid",value:function(e){return"string"==typeof e&&/^!?[^\s\.!]+(\.[^\s\.!]+)*$/.test(e)}},{key:"compare",value:function(e,t){if(e===t)return 0;var n=e.split("."),r=t.split(".");if(n.length===r.length){var i=/(?:^|\.)\*(?:$|\.)/g,a=e.match(i),o=t.match(i),u=a?a.length:0,l=o?o.length:0;if(u===l){var s=0===e.indexOf("!"),c=0===t.indexOf("!");if(s===c)return t>e?-1:1;var f=s?e.slice(1):e,v=c?t.slice(1):t;return f===v?s?1:-1:v>f?-1:1}return u>l?-1:1}return n.length<r.length?-1:1}},{key:"sort",value:function(t){return t.sort(e.compare)}},{key:"union",value:function(t,n,r){var i=void 0,a=void 0,o=void 0;u["default"].eachRight(t,function(r,l){if(o=n.indexOf(r),o>=0&&n.splice(o,1),0===r.indexOf("!")){if(i=r.slice(1),n.indexOf(i)>=0)return t.splice(l,1),!0;u["default"].eachRight(n,function(n,r){n.indexOf("!")<0&&(a=e.toRegExp(n),a.test(i)&&t.splice(l,1))})}else o=n.indexOf("!"+r),o>=0&&n.splice(o,1)});var l=t.concat(n);return void 0===r||r===!0?e.sort(l):l}}]),e}();t["default"]=c},function(e,t){"use strict";function n(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function r(e,t){if(!e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!t||"object"!=typeof t&&"function"!=typeof t?e:t}function i(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function, not "+typeof t);e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}}),t&&(Object.setPrototypeOf?Object.setPrototypeOf(e,t):e.__proto__=t)}Object.defineProperty(t,"__esModule",{value:!0});var a=function(e){function t(){var e=arguments.length<=0||void 0===arguments[0]?"":arguments[0];n(this,t);var i=r(this,Object.getPrototypeOf(t).call(this,e));return i.name=i.constructor.name,Object.defineProperty(i,"name",{enumerable:!1,writable:!1,value:"NotationError"}),Object.defineProperty(i,"message",{enumerable:!1,writable:!0,value:e}),Error.hasOwnProperty("captureStackTrace")?Error.captureStackTrace(i,i.constructor):Object.defineProperty(i,"stack",{enumerable:!1,writable:!1,value:new Error(e).stack}),i}return i(t,e),t}(Error);t["default"]=a}])});

},{}]},{},[1])(1)
});