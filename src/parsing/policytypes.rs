#![rustfmt::skip]
/**
Generated though:
1) Verbatim copy of the `cenum nsContentPolicyType ..` block from
  https://searchfox.org/mozilla-central/source/dom/base/nsIContentPolicy.idl
2) but rustified through "pub enum", the allow-non-camel-case annotation
3)  and the derive() block
 */

/// FIXME: Generate this with a build-time script

use strum_macros::{EnumString, IntoStaticStr};
  /**
   * The type of nsIContentPolicy::TYPE_*
   */
  #[allow(non_camel_case_types)]
  #[derive(Debug, PartialEq, EnumString, IntoStaticStr, Serialize, Deserialize)]
  pub enum nsContentPolicyType {
    /**
     * Indicates a unset or bogus policy type.
     */
    TYPE_INVALID = 0,

    /**
     * Gecko/Firefox developers: Avoid using TYPE_OTHER. Especially for
     * requests that are coming from webpages. Or requests in general which
     * you expect that security checks will be done on.
     * Always use a more specific type if one is available. And do not hesitate
     * to add more types as appropriate.
     * But if you are fairly sure that no one would care about your more specific
     * type, then it's ok to use TYPE_OTHER.
     *
     * Extension developers: Whenever it is reasonable, use one of the existing
     * content types. If none of the existing content types are right for
     * something you are doing, file a bug in the Core/DOM component that
     * includes a patch that adds your new content type to the end of the list of
     * TYPE_* constants here. But, don't start using your new content type until
     * your patch has been accepted, because it will be uncertain what exact
     * value and name your new content type will have; in that interim period,
     * use TYPE_OTHER. In your patch, document your new content type in the style
     * of the existing ones. In the bug you file, provide a more detailed
     * description of the new type of content you want Gecko to support, so that
     * the existing implementations of nsIContentPolicy can be properly modified
     * to deal with that new type of content.
     *
     * Implementations of nsIContentPolicy should treat this the same way they
     * treat unknown types, because existing users of TYPE_OTHER may be converted
     * to use new content types.
     *
     * Note that the TYPE_INTERNAL_* constants are never passed to content
     * policy implementations.  They are mapped to other TYPE_* constants, and
     * are only intended for internal usage inside Gecko.
     */
    TYPE_OTHER = 1,

    /**
     * Indicates an executable script (such as JavaScript).
     */
    TYPE_SCRIPT = 2,

    /**
     * Indicates an image (e.g., IMG elements).
     */
    TYPE_IMAGE = 3,

    /**
     * Indicates a stylesheet (e.g., STYLE elements).
     */
    TYPE_STYLESHEET = 4,

    /**
     * Indicates a generic object (plugin-handled content typically falls under
     * this category).
     */
    TYPE_OBJECT = 5,

    /**
     * Indicates a document at the top-level (i.e., in a browser).
     */
    TYPE_DOCUMENT = 6,

    /**
     * Indicates a document contained within another document (e.g., IFRAMEs,
     * FRAMES, and OBJECTs).
     */
    TYPE_SUBDOCUMENT = 7,

    /*
     * XXX: nsContentPolicyType = 8 used to inicate a timed refresh request.
     */

    /*
     * XXX: nsContentPolicyType = 9 used to inicate an XBL binding request.
     */

    /**
     * Indicates a ping triggered by a click on <A PING="..."> element.
     */
    TYPE_PING = 10,

    /**
     * Indicates an XMLHttpRequest. Also used for document.load and for EventSource.
     */
    TYPE_XMLHTTPREQUEST = 11,

    /**
     * Indicates a request by a plugin.
     */
    TYPE_OBJECT_SUBREQUEST = 12,

    /**
     * Indicates a DTD loaded by an XML document.
     */
    TYPE_DTD = 13,

    /**
     * Indicates a font loaded via @font-face rule.
     */
    TYPE_FONT = 14,

    /**
     * Indicates a video or audio load.
     */
    TYPE_MEDIA = 15,

    /**
     * Indicates a WebSocket load.
     */
    TYPE_WEBSOCKET = 16,

    /**
     * Indicates a Content Security Policy report.
     */
    TYPE_CSP_REPORT = 17,

    /**
     * Indicates a style sheet transformation.
     */
    TYPE_XSLT = 18,

    /**
     * Indicates a beacon post.
     */
    TYPE_BEACON = 19,

    /**
     * Indicates a load initiated by the fetch() function from the Fetch
     * specification.
     */
    TYPE_FETCH = 20,

    /**
     * Indicates a <img srcset> or <picture> request.
     */
    TYPE_IMAGESET = 21,

    /**
     * Indicates a web manifest.
     */
    TYPE_WEB_MANIFEST = 22,

    /**
     * Indicates an internal constant for scripts loaded through script
     * elements.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_SCRIPT = 23,

    /**
     * Indicates an internal constant for scripts loaded through a dedicated
     * worker.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_WORKER = 24,

    /**
     * Indicates an internal constant for scripts loaded through a shared
     * worker.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_SHARED_WORKER = 25,

    /**
     * Indicates an internal constant for content loaded from embed elements.
     *
     * This will be mapped to TYPE_OBJECT.
     */
    TYPE_INTERNAL_EMBED = 26,

    /**
     * Indicates an internal constant for content loaded from object elements.
     *
     * This will be mapped to TYPE_OBJECT.
     */
    TYPE_INTERNAL_OBJECT = 27,

    /**
     * Indicates an internal constant for content loaded from frame elements.
     *
     * This will be mapped to TYPE_SUBDOCUMENT.
     */
    TYPE_INTERNAL_FRAME = 28,

    /**
     * Indicates an internal constant for content loaded from iframe elements.
     *
     * This will be mapped to TYPE_SUBDOCUMENT.
     */
    TYPE_INTERNAL_IFRAME = 29,

    /**
     * Indicates an internal constant for content loaded from audio elements.
     *
     * This will be mapped to TYPE_MEDIA.
     */
    TYPE_INTERNAL_AUDIO = 30,

    /**
     * Indicates an internal constant for content loaded from video elements.
     *
     * This will be mapped to TYPE_MEDIA.
     */
    TYPE_INTERNAL_VIDEO = 31,

    /**
     * Indicates an internal constant for content loaded from track elements.
     *
     * This will be mapped to TYPE_MEDIA.
     */
    TYPE_INTERNAL_TRACK = 32,

    /**
     * Indicates an internal constant for an XMLHttpRequest.
     *
     * This will be mapped to TYPE_XMLHTTPREQUEST.
     */
    TYPE_INTERNAL_XMLHTTPREQUEST = 33,

    /**
     * Indicates an internal constant for EventSource.
     *
     * This will be mapped to TYPE_XMLHTTPREQUEST.
     */
    TYPE_INTERNAL_EVENTSOURCE = 34,

    /**
     * Indicates an internal constant for scripts loaded through a service
     * worker.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_SERVICE_WORKER = 35,

    /**
     * Indicates an internal constant for *preloaded* scripts
     * loaded through script elements.
     *
     * This will be mapped to TYPE_SCRIPT before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_SCRIPT_PRELOAD = 36,

    /**
     * Indicates an internal constant for normal images.
     *
     * This will be mapped to TYPE_IMAGE before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_IMAGE = 37,

    /**
     * Indicates an internal constant for *preloaded* images.
     *
     * This will be mapped to TYPE_IMAGE before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_IMAGE_PRELOAD = 38,

    /**
     * Indicates an internal constant for normal stylesheets.
     *
     * This will be mapped to TYPE_STYLESHEET before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_STYLESHEET = 39,

    /**
     * Indicates an internal constant for *preloaded* stylesheets.
     *
     * This will be mapped to TYPE_STYLESHEET before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_STYLESHEET_PRELOAD = 40,

    /**
     * Indicates an internal constant for favicon.
     *
     * This will be mapped to TYPE_IMAGE before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_IMAGE_FAVICON = 41,

    /**
     * Indicates an importScripts() inside a worker script.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_WORKER_IMPORT_SCRIPTS = 42,

    /**
     * Indicates an save-as link download from the front-end code.
     */
    TYPE_SAVEAS_DOWNLOAD = 43,

    /**
     * Indicates a speculative connection.
     */
    TYPE_SPECULATIVE = 44,

    /**
     * Indicates an internal constant for ES6 module scripts
     * loaded through script elements or an import statement.
     *
     * This will be mapped to TYPE_SCRIPT before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_MODULE = 45,

    /**
     * Indicates an internal constant for *preloaded* ES6 module scripts
     * loaded through script elements or an import statement.
     *
     * This will be mapped to TYPE_SCRIPT before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_MODULE_PRELOAD = 46,

    /**
     * Indicates a DTD loaded by an XML document the URI of which could
     * not be mapped to a known local DTD.
     */
    TYPE_INTERNAL_DTD = 47,

    /**
     * Indicates a TYPE_INTERNAL_DTD which will not be blocked no matter
     * what principal is being loaded from.
     */
    TYPE_INTERNAL_FORCE_ALLOWED_DTD = 48,

    /**
     * Indicates an internal constant for scripts loaded through an
     * audioWorklet.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_AUDIOWORKLET = 49,

    /**
     * Indicates an internal constant for scripts loaded through an
     * paintWorklet.
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
     */
    TYPE_INTERNAL_PAINTWORKLET = 50,

    /**
     * Same as TYPE_FONT but indicates this is a <link rel=preload as=font>
     * preload initiated load.
     */
    TYPE_INTERNAL_FONT_PRELOAD = 51,

    /**
     * Indicates the load of a (Firefox-internal) script through ChromeUtils
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
    */
    TYPE_INTERNAL_CHROMEUTILS_COMPILED_SCRIPT = 52,

    /**
     * Indicates the load of a script through FrameMessageManager
     *
     * This will be mapped to TYPE_SCRIPT before being passed to content policy
     * implementations.
    */
    TYPE_INTERNAL_FRAME_MESSAGEMANAGER_SCRIPT = 53,

    /**
     * Indicates an internal constant for *preloaded* fetch
     * loaded through link elements.
     *
     * This will be mapped to TYPE_FETCH before being passed
     * to content policy implementations.
     */
    TYPE_INTERNAL_FETCH_PRELOAD = 54,

    /* When adding new content types, please update
     * NS_CP_ContentTypeName, nsCSPContext, CSP_ContentTypeToDirective,
     * DoContentSecurityChecks, all nsIContentPolicy implementations, the
     * static_assert in dom/cache/DBSchema.cpp, ChannelWrapper.webidl,
     * ChannelWrapper.cpp, PermissionManager.cpp,
     * IPCMessageUtilsSpecializations.h, and other things that are not
     * listed here that are related to nsIContentPolicy. */
  }
