/**
 * SPDX-FileCopyrightText: (C) 2021 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 * SPDX-License-Identifier: MPL-2.0
 */

#include <podofo/private/PdfDeclarationsPrivate.h>
#include "PdfPage.h"

#include <algorithm>
#include <limits>
#include <vector>

#include "PdfDocument.h"
#include "PdfMath.h"
#include "PdfXObjectForm.h"
#include "PdfContentStreamReader.h"

#include <podofo/auxiliary/StateStack.h>

using namespace std;
using namespace PoDoFo;

// The distance below which two coordinates are considered the same, in page units
constexpr double COORDINATE_EPSILON = 0.001;

namespace
{
    // The graphics state that matters to the drawings
    // A rectangle in page coordinates
    struct Box
    {
        double MinX = -std::numeric_limits<double>::max();
        double MinY = -std::numeric_limits<double>::max();
        double MaxX = std::numeric_limits<double>::max();
        double MaxY = std::numeric_limits<double>::max();

        bool IsEmpty() const { return MinX > MaxX || MinY > MaxY; }

        void Intersect(const Box& other)
        {
            MinX = std::max(MinX, other.MinX);
            MinY = std::max(MinY, other.MinY);
            MaxX = std::min(MaxX, other.MaxX);
            MaxY = std::min(MaxY, other.MaxY);
        }
    };

    struct GraphicsState
    {
        Matrix CTM;
        double LineWidth = 1;
        PdfPaintColor FillColor;
        PdfPaintColor StrokeColor;
        // Bounding box of the clipping path in use
        Box Clip;
    };

    // A subpath being built, with its points already transformed to page coordinates
    struct SubPath
    {
        vector<Vector2> Points;
        bool HasCurve = false;
        bool IsRectangle = false;
        bool Closed = false;
    };

    using GraphicsStateStack = StateStack<GraphicsState>;
}

static void setColor(PdfPaintColor& color, PdfPaintColorSpace colorSpace, const PdfVariantStack& operands,
    unsigned count)
{
    color = PdfPaintColor();
    color.ColorSpace = colorSpace;
    for (unsigned i = 0; i < count; i++)
    {
        // The operands are pushed in reverse order
        double component;
        if (operands[count - 1 - i].TryGetReal(component))
            color.Components[i] = component;
    }
}

// The color spaces that are not device ones are reported as unknown, but the
// components of the ICCBased ones behave as the device space of the same size
static void setColorFromComponents(PdfPaintColor& color, const PdfVariantStack& operands)
{
    unsigned count = 0;
    for (unsigned i = 0; i < operands.GetSize(); i++)
    {
        double component;
        if (!operands[i].TryGetReal(component))
            break;

        count++;
    }

    switch (count)
    {
        case 1:
            setColor(color, PdfPaintColorSpace::Gray, operands, 1);
            break;
        case 3:
            setColor(color, PdfPaintColorSpace::RGB, operands, 3);
            break;
        case 4:
            setColor(color, PdfPaintColorSpace::CMYK, operands, 4);
            break;
        default:
            color = PdfPaintColor();
            break;
    }
}

// Determine if the points describe an axis aligned rectangle
static bool isAxisAlignedRectangle(const vector<Vector2>& points)
{
    if (points.size() < 4 || points.size() > 5)
        return false;

    // A closed path may repeat the first point
    unsigned count = (unsigned)points.size();
    if (count == 5)
    {
        if (std::abs(points[4].X - points[0].X) > COORDINATE_EPSILON
            || std::abs(points[4].Y - points[0].Y) > COORDINATE_EPSILON)
        {
            return false;
        }
    }

    for (unsigned i = 0; i < 4; i++)
    {
        auto& current = points[i];
        auto& next = points[(i + 1) % 4];
        bool horizontal = std::abs(current.Y - next.Y) <= COORDINATE_EPSILON;
        bool vertical = std::abs(current.X - next.X) <= COORDINATE_EPSILON;
        if (!horizontal && !vertical)
            return false;
    }

    return true;
}

// Fill the visible bounding box and the clipping box of an entry. Return false
// when the drawing is hidden by the clipping path or is smaller than minSize
static bool applyClip(PdfGraphicsEntry& entry, double minX, double minY, double maxX, double maxY,
    const Box& clip, double minSize)
{
    double visibleMinX = std::max(minX, clip.MinX);
    double visibleMinY = std::max(minY, clip.MinY);
    double visibleMaxX = std::min(maxX, clip.MaxX);
    double visibleMaxY = std::min(maxY, clip.MaxY);
    if (visibleMinX > visibleMaxX || visibleMinY > visibleMaxY)
    {
        // The clipping path hides the drawing entirely
        return false;
    }

    entry.X = visibleMinX;
    entry.Y = visibleMinY;
    entry.Width = visibleMaxX - visibleMinX;
    entry.Height = visibleMaxY - visibleMinY;
    entry.ClipX = clip.MinX;
    entry.ClipY = clip.MinY;
    entry.ClipWidth = clip.MaxX - clip.MinX;
    entry.ClipHeight = clip.MaxY - clip.MinY;

    return std::max(entry.Width, entry.Height) >= minSize;
}

static void addEntry(vector<PdfGraphicsEntry>& entries, const SubPath& subPath, const GraphicsState& state,
    bool stroked, bool filled, int pageIndex, const Matrix* rotation, double minSize)
{
    if (subPath.Points.size() < 2)
    {
        // A subpath that draws nothing, as the ones that only move the current point
        return;
    }

    double minX = std::numeric_limits<double>::max();
    double minY = std::numeric_limits<double>::max();
    double maxX = -std::numeric_limits<double>::max();
    double maxY = -std::numeric_limits<double>::max();
    for (auto& point : subPath.Points)
    {
        auto rotated = rotation == nullptr ? point : point * (*rotation);
        minX = std::min(minX, rotated.X);
        minY = std::min(minY, rotated.Y);
        maxX = std::max(maxX, rotated.X);
        maxY = std::max(maxY, rotated.Y);
    }

    PdfGraphicsEntry entry;
    entry.Type = PdfGraphicsEntryType::Path;
    entry.Page = pageIndex;
    if (!applyClip(entry, minX, minY, maxX, maxY, state.Clip, minSize))
        return;

    entry.Stroked = stroked;
    entry.Filled = filled;
    entry.FillColor = state.FillColor;
    entry.StrokeColor = state.StrokeColor;
    if (stroked)
    {
        // The line width is expressed in user space: scale it to page units
        entry.LineWidth = (Vector2(state.LineWidth, 0) * state.CTM.GetScalingRotation()).GetLength();
    }

    entry.IsLine = !subPath.HasCurve && !subPath.Closed && subPath.Points.size() == 2;
    entry.IsRectangle = subPath.IsRectangle
        || (!subPath.HasCurve && isAxisAlignedRectangle(subPath.Points));

    if (entry.IsLine)
    {
        auto first = rotation == nullptr ? subPath.Points[0] : subPath.Points[0] * (*rotation);
        auto second = rotation == nullptr ? subPath.Points[1] : subPath.Points[1] * (*rotation);
        entry.X1 = first.X;
        entry.Y1 = first.Y;
        entry.X2 = second.X;
        entry.Y2 = second.Y;
    }
    else
    {
        entry.X1 = minX;
        entry.Y1 = minY;
        entry.X2 = maxX;
        entry.Y2 = maxY;
    }

    entries.push_back(entry);
}

static void addImageEntry(vector<PdfGraphicsEntry>& entries, const GraphicsState& state, unsigned objectNumber,
    int pageIndex, const Matrix* rotation, double minSize)
{
    // An image is painted in the unit square of the current user space
    Vector2 corners[4] = { Vector2(0, 0), Vector2(1, 0), Vector2(1, 1), Vector2(0, 1) };
    double minX = std::numeric_limits<double>::max();
    double minY = std::numeric_limits<double>::max();
    double maxX = -std::numeric_limits<double>::max();
    double maxY = -std::numeric_limits<double>::max();
    for (auto& corner : corners)
    {
        auto point = corner * state.CTM;
        if (rotation != nullptr)
            point = point * (*rotation);

        minX = std::min(minX, point.X);
        minY = std::min(minY, point.Y);
        maxX = std::max(maxX, point.X);
        maxY = std::max(maxY, point.Y);
    }

    PdfGraphicsEntry entry;
    entry.Type = PdfGraphicsEntryType::Image;
    entry.Page = pageIndex;
    if (!applyClip(entry, minX, minY, maxX, maxY, state.Clip, minSize))
        return;

    entry.X1 = minX;
    entry.Y1 = minY;
    entry.X2 = maxX;
    entry.Y2 = maxY;
    entry.IsRectangle = true;
    entry.ImageObject = objectNumber;
    entries.push_back(entry);
}

void PdfPage::ExtractGraphicsTo(vector<PdfGraphicsEntry>& entries, double minSize) const
{
    entries.clear();

    unique_ptr<Matrix> rotation;
    double teta;
    if (this->HasRotation(teta))
        rotation = std::make_unique<Matrix>(PoDoFo::GetFrameRotationTransform(this->GetRectRaw(), teta));

    int pageIndex = (int)this->GetPageNumber() - 1;
    GraphicsStateStack states;
    // Nothing is drawn outside of the page
    auto pageRect = this->GetRect();
    states.Current->Clip.MinX = pageRect.X;
    states.Current->Clip.MinY = pageRect.Y;
    states.Current->Clip.MaxX = pageRect.X + pageRect.Width;
    states.Current->Clip.MaxY = pageRect.Y + pageRect.Height;
    // The clipping path is set by W or W* and takes effect at the next painting
    bool pendingClip = false;
    vector<SubPath> path;
    Vector2 currentPoint;
    Vector2 subPathStart;
    bool hasCurrentPoint = false;
    // Count of the states pushed when entering a form XObject
    vector<unsigned> xObjectStateIndices;

    auto beginSubPath = [&](const Vector2& point) {
        path.push_back(SubPath());
        path.back().Points.push_back(point);
        currentPoint = point;
        subPathStart = point;
        hasCurrentPoint = true;
    };

    auto appendPoint = [&](const Vector2& point, bool curve) {
        if (!hasCurrentPoint)
        {
            beginSubPath(point);
            return;
        }

        if (path.size() == 0)
            path.push_back(SubPath());

        path.back().Points.push_back(point);
        if (curve)
            path.back().HasCurve = true;

        currentPoint = point;
    };

    auto paintPath = [&](bool stroked, bool filled) {
        if (stroked || filled)
        {
            for (auto& subPath : path)
                addEntry(entries, subPath, *states.Current, stroked, filled, pageIndex, rotation.get(), minSize);
        }

        if (pendingClip)
        {
            // Intersect the clipping path in use with the bounding box of the path.
            // NOTE: The bounding box is an approximation of the path, which is
            // enough to tell the visible area of a drawing
            Box box;
            box.MinX = std::numeric_limits<double>::max();
            box.MinY = std::numeric_limits<double>::max();
            box.MaxX = -std::numeric_limits<double>::max();
            box.MaxY = -std::numeric_limits<double>::max();
            for (auto& subPath : path)
            {
                for (auto& point : subPath.Points)
                {
                    auto rotated = rotation == nullptr ? point : point * (*rotation);
                    box.MinX = std::min(box.MinX, rotated.X);
                    box.MinY = std::min(box.MinY, rotated.Y);
                    box.MaxX = std::max(box.MaxX, rotated.X);
                    box.MaxY = std::max(box.MaxY, rotated.Y);
                }
            }

            if (!box.IsEmpty())
                states.Current->Clip.Intersect(box);

            pendingClip = false;
        }

        path.clear();
        hasCurrentPoint = false;
    };

    PdfContentStreamReader reader(*this);
    PdfContent content;
    while (reader.TryReadNext(content))
    {
        switch (content.Type)
        {
            case PdfContentType::Operator:
            {
                if ((content.Warnings & PdfContentWarnings::InvalidOperator) != PdfContentWarnings::None)
                    continue;

                auto& state = *states.Current;
                switch (content.Operator)
                {
                    case PdfOperator::q:
                    {
                        states.Push();
                        break;
                    }
                    case PdfOperator::Q:
                    {
                        (void)states.PopLenient();
                        break;
                    }
                    case PdfOperator::cm:
                    {
                        Matrix matrix = Matrix::FromCoefficients(
                            content.Stack[5].GetReal(), content.Stack[4].GetReal(), content.Stack[3].GetReal(),
                            content.Stack[2].GetReal(), content.Stack[1].GetReal(), content.Stack[0].GetReal());
                        state.CTM = matrix * state.CTM;
                        break;
                    }
                    case PdfOperator::w:
                    {
                        state.LineWidth = content.Stack[0].GetReal();
                        break;
                    }
                    // Path construction
                    case PdfOperator::m:
                    {
                        Vector2 point(content.Stack[1].GetReal(), content.Stack[0].GetReal());
                        beginSubPath(point * state.CTM);
                        break;
                    }
                    case PdfOperator::l:
                    {
                        Vector2 point(content.Stack[1].GetReal(), content.Stack[0].GetReal());
                        appendPoint(point * state.CTM, false);
                        break;
                    }
                    case PdfOperator::c:
                    {
                        // The bounding box of the control points contains the curve
                        for (int i = 2; i >= 0; i--)
                        {
                            Vector2 point(content.Stack[i * 2 + 1].GetReal(), content.Stack[i * 2].GetReal());
                            appendPoint(point * state.CTM, true);
                        }
                        break;
                    }
                    case PdfOperator::v:
                    case PdfOperator::y:
                    {
                        for (int i = 1; i >= 0; i--)
                        {
                            Vector2 point(content.Stack[i * 2 + 1].GetReal(), content.Stack[i * 2].GetReal());
                            appendPoint(point * state.CTM, true);
                        }
                        break;
                    }
                    case PdfOperator::h:
                    {
                        if (path.size() != 0)
                        {
                            path.back().Closed = true;
                            appendPoint(subPathStart, false);
                        }
                        break;
                    }
                    case PdfOperator::re:
                    {
                        double height = content.Stack[0].GetReal();
                        double width = content.Stack[1].GetReal();
                        double y = content.Stack[2].GetReal();
                        double x = content.Stack[3].GetReal();
                        SubPath rectangle;
                        rectangle.Closed = true;
                        rectangle.IsRectangle = true;
                        rectangle.Points.push_back(Vector2(x, y) * state.CTM);
                        rectangle.Points.push_back(Vector2(x + width, y) * state.CTM);
                        rectangle.Points.push_back(Vector2(x + width, y + height) * state.CTM);
                        rectangle.Points.push_back(Vector2(x, y + height) * state.CTM);
                        path.push_back(std::move(rectangle));
                        currentPoint = Vector2(x, y) * state.CTM;
                        subPathStart = currentPoint;
                        hasCurrentPoint = true;
                        break;
                    }
                    // Path painting
                    case PdfOperator::S:
                    case PdfOperator::s:
                    {
                        paintPath(true, false);
                        break;
                    }
                    case PdfOperator::f:
                    case PdfOperator::F:
                    case PdfOperator::f_Star:
                    {
                        paintPath(false, true);
                        break;
                    }
                    case PdfOperator::B:
                    case PdfOperator::B_Star:
                    case PdfOperator::b:
                    case PdfOperator::b_Star:
                    {
                        paintPath(true, true);
                        break;
                    }
                    case PdfOperator::n:
                    {
                        // The path is not painted: it only sets the clipping path
                        paintPath(false, false);
                        break;
                    }
                    // Clipping paths
                    case PdfOperator::W:
                    case PdfOperator::W_Star:
                    {
                        pendingClip = true;
                        break;
                    }
                    // Color
                    case PdfOperator::g:
                    {
                        setColor(state.FillColor, PdfPaintColorSpace::Gray, content.Stack, 1);
                        break;
                    }
                    case PdfOperator::G:
                    {
                        setColor(state.StrokeColor, PdfPaintColorSpace::Gray, content.Stack, 1);
                        break;
                    }
                    case PdfOperator::rg:
                    {
                        setColor(state.FillColor, PdfPaintColorSpace::RGB, content.Stack, 3);
                        break;
                    }
                    case PdfOperator::RG:
                    {
                        setColor(state.StrokeColor, PdfPaintColorSpace::RGB, content.Stack, 3);
                        break;
                    }
                    case PdfOperator::k:
                    {
                        setColor(state.FillColor, PdfPaintColorSpace::CMYK, content.Stack, 4);
                        break;
                    }
                    case PdfOperator::K:
                    {
                        setColor(state.StrokeColor, PdfPaintColorSpace::CMYK, content.Stack, 4);
                        break;
                    }
                    case PdfOperator::sc:
                    case PdfOperator::scn:
                    {
                        setColorFromComponents(state.FillColor, content.Stack);
                        break;
                    }
                    case PdfOperator::SC:
                    case PdfOperator::SCN:
                    {
                        setColorFromComponents(state.StrokeColor, content.Stack);
                        break;
                    }
                    case PdfOperator::cs:
                    {
                        // The color space is changed: the color is unknown until it
                        // is set again
                        state.FillColor = PdfPaintColor();
                        break;
                    }
                    case PdfOperator::CS:
                    {
                        state.StrokeColor = PdfPaintColor();
                        break;
                    }
                    default:
                        break;
                }

                break;
            }
            case PdfContentType::DoXObject:
            {
                if (content.XObject == nullptr)
                    break;

                if (content.XObject->GetType() == PdfXObjectType::Image)
                {
                    addImageEntry(entries, *states.Current,
                        content.XObject->GetObject().GetIndirectReference().ObjectNumber(), pageIndex, rotation.get(),
                        minSize);
                    break;
                }

                if (content.XObject->GetType() == PdfXObjectType::Form)
                {
                    // The content of the form is read next: draw it with the matrix
                    // of the form applied to the current one
                    xObjectStateIndices.push_back(states.GetSize());
                    states.Push();
                    auto& form = (const PdfXObjectForm&)*content.XObject;
                    states.Current->CTM = form.GetMatrix() * states.Current->CTM;
                }

                break;
            }
            case PdfContentType::EndXObjectForm:
            {
                if (xObjectStateIndices.size() != 0)
                {
                    states.Pop(states.GetSize() - xObjectStateIndices.back());
                    xObjectStateIndices.pop_back();
                }

                break;
            }
            default:
                break;
        }
    }
}
