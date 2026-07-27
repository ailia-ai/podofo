/**
 * SPDX-FileCopyrightText: (C) 2005 Dominik Seichter <domseichter@web.de>
 * SPDX-FileCopyrightText: (C) 2020 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef PDF_PAGE_H
#define PDF_PAGE_H

#include "PdfDeclarations.h"

#include <podofo/auxiliary/Rect.h>

#include "PdfAnnotationCollection.h"
#include "PdfCanvas.h"
#include "PdfContents.h"
#include "PdfField.h"
#include "PdfObject.h"
#include "PdfResources.h"

namespace PoDoFo {

class PdfDocument;
class PdfDictionary;
class PdfIndirectObjectList;
class InputStream;

struct PdfTextEntry final
{
    std::string Text;
    int Page;
    double X;
    double Y;
    double Length;
    nullable<Rect> BoundingBox;
    double TextMatrix[6];       // Combined T_m * CTM (page coordinates)
    double FontSize;
    std::string FontName;
    double FontScale = 1;
    double CharSpacing = 0;
    double WordSpacing = 0;
    double StringLength;
    double LineSpacing;
    struct PdfTextColor
    {
        struct PdfTextGrayColor
        {
            double Gray = -1;
        } GrayColor;
        struct PdfTextRGBColor
        {
            double R = -1;
            double G = -1;
            double B = -1;
        } RGBColor;
        struct PdfTextCMYKColor
        {
            double C = -1;
            double M = -1;
            double Y = -1;
            double K = -1;
        } CMYKColor;
    } TextColor;
    // Identifies the text showing operators (Tj, TJ, ' and ") the entry was
    // extracted from, so that they can be located in the content stream, eg. to
    // remove the text of single entries. Operators are numbered from zero in
    // stream order, separately for every canvas: SourceCanvas is the object
    // number of the form XObject the operators belong to, or zero for the
    // content of the page itself. SourceOperatorsValid is false when the entry
    // spans more than one canvas, in which case the range is meaningless
    struct PdfTextSource
    {
        unsigned Canvas = 0;
        unsigned FirstOperator = 0;
        unsigned LastOperator = 0;
        bool IsValid = false;
    } Source;
};

struct PdfTextExtractParams
{
    nullable<Rect> ClipRect;
    PdfTextExtractFlags Flags;
};

/** The color space a color belongs to
 */
enum class PdfPaintColorSpace : uint8_t
{
    /** The color is unknown, as it belongs to a color space that is not converted,
     * a Separation or a Pattern one
     */
    None = 0,
    Gray = 1,
    RGB = 2,
    CMYK = 3,
};

/** The color a path is painted with
 */
struct PdfPaintColor final
{
    PdfPaintColorSpace ColorSpace = PdfPaintColorSpace::None;
    /** The components of the color: one for Gray, three for RGB and four for
     * CMYK. The unused ones are zero. The components of an ICCBased color space
     * are reported as the device space with the same number of components
     */
    double Components[4] = { 0, 0, 0, 0 };
};

enum class PdfGraphicsEntryType : uint8_t
{
    /** A painted path: the rules of a table, the frame of a figure, ... */
    Path = 0,
    /** The placement of an image XObject */
    Image = 1,
};

/** A drawing of a page, in page coordinates. See PdfPage::ExtractGraphicsTo()
 */
struct PdfGraphicsEntry final
{
    PdfGraphicsEntryType Type = PdfGraphicsEntryType::Path;
    int Page = 0;
    /** Visible bounding box of the drawing, that is its bounding box intersected
     * with the clipping path in use. NOTE: The bounding box of a curve is the one
     * of its control points, which contains the curve
     */
    double X = 0;
    double Y = 0;
    double Width = 0;
    double Height = 0;
    /** Endpoints of the segment when the path is a single straight line, before
     * clipping. They are the lower left and the upper right corners of the
     * bounding box otherwise
     */
    double X1 = 0;
    double Y1 = 0;
    double X2 = 0;
    double Y2 = 0;
    /** Bounding box of the clipping path in use, which is the box of the page
     * when there is none
     */
    double ClipX = 0;
    double ClipY = 0;
    double ClipWidth = 0;
    double ClipHeight = 0;
    /** True when the path is a single straight segment, as the rules of a table */
    bool IsLine = false;
    /** True when the path is an axis aligned rectangle, as the frame of a figure */
    bool IsRectangle = false;
    bool Stroked = false;
    bool Filled = false;
    /** Width of the stroke in page units, zero when the path is not stroked */
    double LineWidth = 0;
    PdfPaintColor FillColor;
    PdfPaintColor StrokeColor;
    /** Object number of the image of an Image entry, zero for a path */
    unsigned ImageObject = 0;
};

/** The text to replace a text showing operator with, so that the text of single
 * text entries can be removed from a content stream. See
 * PdfPage::ComputeTextRemovalTo()
 */
struct PdfTextReplacement final
{
    // Canvas and index of the operator, as in PdfTextEntry::Source
    unsigned Canvas = 0;
    unsigned Operator = 0;
    // The operators to write in place of the original one. It is empty when the
    // original operator is to be removed
    std::string Text;
};

// Collects the details needed to rewrite the text showing operators. It is an
// implementation detail of the text extraction
struct PdfTextExtractCollector;

typedef void (*GetImageObjectCallback)(const PdfObject);

/** PdfPage is one page in the pdf document.
 *  It is possible to draw on a page using a PdfPainter object.
 *  Every document needs at least one page.
 */
class PODOFO_API PdfPage final : public PdfDictionaryElement, public PdfCanvas
{
    PODOFO_UNIT_TEST(PdfPageTest);
    friend class PdfPageCollection;
    friend class PdfDocument;

private:
    /** Create a new PdfPage object.
     *  \param size a Rect specifying the size of the page (i.e the /MediaBox key) in PDF units
     *  \param parent add the page to this parent
     */
    PdfPage(PdfDocument& parent, const Rect& size);

    /** Create a PdfPage based on an existing PdfObject
     *  \param obj an existing PdfObject
     *  \param listOfParents a list of PdfObjects that are
     *                       parents of this page and can be
     *                       queried for inherited attributes.
     *                       The last object in the list is the
     *                       most direct parent of this page.
     */
    PdfPage(PdfObject& obj);
    PdfPage(PdfObject& obj, std::vector<PdfObject*>&& parents);

public:
    void ExtractTextTo(std::vector<PdfTextEntry>& entries,
        const PdfTextExtractParams& params) const;

    void ExtractTextTo(std::vector<PdfTextEntry>& entries,
        const std::string_view& pattern = { },
        const PdfTextExtractParams& params = { }) const;

    /** Extract the drawings of the page: the painted paths, that is the rules of
     * the tables and the frames of the figures, and the placement of the images
     *
     * \param entries the drawings, in page coordinates and in drawing order
     * \param minSize the drawings whose visible bounding box is smaller than this
     *      value in both directions are not reported. Zero reports all of them
     * \remarks The paths are reported one subpath at a time, so that the rules
     *      drawn by a single path are reported separately. The paths that are
     *      neither stroked nor filled, as the ones that only set the clipping
     *      path, and the ones the clipping path hides entirely, are not reported
     * \remarks The coordinates are the ones the text extraction reports: the CTM
     *      is applied, hence the content of a form XObject is reported with the
     *      matrix of every placement applied, the origin is the lower left corner
     *      of the page and the rotation of the page is applied
     */
    void ExtractGraphicsTo(std::vector<PdfGraphicsEntry>& entries, double minSize = 0) const;

    /** Determine how to rewrite the content stream to remove the text of the
     * given entries, leaving the text of all the other entries untouched
     *
     * \param replacements the text showing operators to rewrite and the text to
     *      write in place of them. Operators that don't need to be rewritten are
     *      not returned
     * \param entryIndices indices of the entries to remove, as returned by
     *      ExtractTextTo() with the same parameters
     * \remarks The text of the entries that are kept is preserved as it is,
     *      including the state it is drawn with. The advance of the removed
     *      glyphs is preserved as well, so that the following text doesn't move
     */
    void ComputeTextRemovalTo(std::vector<PdfTextReplacement>& replacements,
        const std::vector<unsigned>& entryIndices,
        const PdfTextExtractParams& params = { }) const;

    Rect GetRect() const;

    Rect GetRectRaw() const override;

    void SetRect(const Rect& rect);

    void SetRectRaw(const Rect& rect);

    bool HasRotation(double& teta) const override;

    // added by Petr P. Petrov 21 Febrary 2010
    /** Set the current page width in PDF Units
     *
     * \returns true if successful, false otherwise
     *
     */
    [[deprecated]] bool SetPageWidth(int newWidth);

    // added by Petr P. Petrov 21 Febrary 2010
    /** Set the current page height in PDF Units
     *
     * \returns true if successful, false otherwise
     *
     */
    [[deprecated]] bool SetPageHeight(int newHeight);

    /** Set the /MediaBox in PDF Units
     * \param rect a Rect in PDF units
     */
    void SetMediaBox(const Rect& rect, bool raw = false);

    /** Set the /CropBox in PDF Units
     * \param rect a Rect in PDF units
     */
    void SetCropBox(const Rect& rect, bool raw = false);

    /** Set the /TrimBox in PDF Units
     * \param rect a Rect in PDF units
     */
    void SetTrimBox(const Rect& rect, bool raw = false);

    /** Set the /BleedBox in PDF Units
     * \param rect a Rect in PDF units
     */
    void SetBleedBox(const Rect& rect, bool raw = false);

    /** Set the /ArtBox in PDF Units
     * \param rect a Rect in PDF units
     */
    void SetArtBox(const Rect& rect, bool raw = false);

    /** Page number inside of the document. The  first page
     *  has the number 1
     *
     *  \returns the number of the page inside of the document
     */
    unsigned GetPageNumber() const;

    /** Creates a Rect with the page size as values which is needed to create a PdfPage object
     *  from an enum which are defined for a few standard page sizes.
     *
     *  \param pageSize the page size you want
     *  \param landscape create a landscape pagesize instead of portrait (by exchanging width and height)
     *  \returns a Rect object which can be passed to the PdfPage constructor
     */
    static Rect CreateStandardPageSize(const PdfPageSize pageSize, bool landscape = false);

    /** Get the current MediaBox (physical page size) in PDF units.
     *  \returns Rect the page box
     */
    Rect GetMediaBox(bool raw = false) const;

    /** Get the current CropBox (visible page size) in PDF units.
     *  \returns Rect the page box
     */
    Rect GetCropBox(bool raw = false) const;

    /** Get the current TrimBox (cut area) in PDF units.
     *  \returns Rect the page box
     */
    Rect GetTrimBox(bool raw = false) const;

    /** Get the current BleedBox (extra area for printing purposes) in PDF units.
     *  \returns Rect the page box
     */
    Rect GetBleedBox(bool raw = false) const;

    /** Get the current ArtBox in PDF units.
     *  \returns Rect the page box
     */
    Rect GetArtBox(bool raw = false) const;

    /** Get the current page rotation (if any), it's a clockwise rotation
     *  \returns int 0, 90, 180 or 270
     */
    int GetRotationRaw() const;

    /** Set the current page rotation.
     *  \param iRotation Rotation to set to the page. Valid value are 0, 90, 180, 270.
     */
    void SetRotationRaw(int rotation);

    /** Move the page at the given index
     */
    void MoveAt(unsigned index);

    template <typename TField>
    TField& CreateField(const std::string_view& name, const Rect& rect, bool rawRect = false);

    PdfField& CreateField(const std::string_view& name, PdfFieldType fieldType, const Rect& rect, bool rawRect = false);

    /** Set an ICC profile for this page
     *
     *  \param csTag a ColorSpace tag
     *  \param stream an input stream from which the ICC profiles data can be read
     *  \param colorComponents the number of colorcomponents of the ICC profile (expected is 1, 3 or 4 components)
     *  \param alternateColorSpace an alternate colorspace to use if the ICC profile cannot be used
     *
     *  \see PdfPainter::SetDependICCProfileColor()
     */
    void SetICCProfile(const std::string_view& csTag, InputStream& stream, int64_t colorComponents,
        PdfColorSpaceType alternateColorSpace = PdfColorSpaceType::DeviceRGB);

public:
    unsigned GetIndex() const { return m_Index; }
    PdfContents& GetOrCreateContents();
    PdfResources& GetOrCreateResources() override;
    inline const PdfContents* GetContents() const { return m_Contents.get(); }
    inline PdfContents* GetContents() { return m_Contents.get(); }
    const PdfContents& MustGetContents() const;
    PdfContents& MustGetContents();
    inline const PdfResources* GetResources() const { return m_Resources.get(); }
    inline PdfResources* GetResources() { return m_Resources.get(); }
    const PdfResources& MustGetResources() const;
    PdfResources& MustGetResources();
    inline PdfAnnotationCollection& GetAnnotations() { return m_Annotations; }
    inline const PdfAnnotationCollection& GetAnnotations() const { return m_Annotations; }
    void RegisterCallback(GetImageObjectCallback callback);

private:
    void extractTextTo(std::vector<PdfTextEntry>& entries, const std::string_view& pattern,
        const PdfTextExtractParams& params, PdfTextExtractCollector* collector) const;

private:
    // To be called by PdfPageCollection
    void FlattenStructure();
    void SetIndex(unsigned index) { m_Index = index; }

    void EnsureResourcesCreated() override;

    PdfObjectStream& GetStreamForAppending(PdfStreamAppendFlags flags) override;

    PdfField& createField(const std::string_view& name, const std::type_info& typeInfo, const Rect& rect, bool rawRect);

    PdfResources* getResources() override;

    PdfObject* getContentsObject() override;

    PdfElement& getElement() override;

    PdfObject* findInheritableAttribute(const std::string_view& name) const;

    PdfObject* findInheritableAttribute(const std::string_view& name, bool& isShallow) const;

    /**
     * Initialize a new page object.
     * m_Contents must be initialized before calling this!
     *
     * \param size page size
     */
    void initNewPage(const Rect& size);

    void ensureContentsCreated();
    void ensureResourcesCreated();

    /** Get the bounds of a specified page box in PDF units.
     * This function is internal, since there are wrappers for all standard boxes
     *  \returns Rect the page box
     */
    Rect getPageBox(const std::string_view& inBox, bool isInheritable, bool raw) const;

    void setPageBox(const std::string_view& inBox, const Rect& rect, bool raw);

private:
    PdfElement& GetElement() = delete;
    const PdfElement& GetElement() const = delete;
    PdfObject* GetContentsObject() = delete;
    const PdfObject* GetContentsObject() const = delete;

private:
    unsigned m_Index;
    std::vector<PdfObject*> m_parents;
    std::unique_ptr<PdfContents> m_Contents;
    std::unique_ptr<PdfResources> m_Resources;
    PdfAnnotationCollection m_Annotations;
    GetImageObjectCallback m_ImageObjectCallback;
};

template<typename TField>
TField& PdfPage::CreateField(const std::string_view& name, const Rect & rect, bool rawRect)
{
    return static_cast<TField&>(createField(name, typeid(TField), rect, rawRect));
}

};

#endif // PDF_PAGE_H
